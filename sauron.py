#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import ssl
import sys
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException, LDAPBindError
except ImportError:
    print("Missing 'ldap3' package. Install with: pip install ldap3==2.9.1", file=sys.stderr)
    sys.exit(1)

BANNER="""                             
            ░░▒▒▒▒▒░░░░▒▒▒▒▒░░            
         ░░▒▒▒▓▓▓▒░░▓▓░░▒▓▓▓▒▒▒░░           
        ░░▒▒▓▓▓▒▒░░▓██▓░░▒▒▓▓▓▒▒░░        
     ░░▒▒▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▒▒░░      
   ░░░▒▒▓▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▓▒▒░░░    
   ░░░▒▒▓▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▓▒▒░░░      ~One eye to bind them all~
     ░░▒▒▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▒▒░░     
      ░░░▒▒▒▓▓▓▒▒░░▓██▓░░▒▒▓▓▓▒▒▒░░░      
        ░░▒▒▒▒▓▓▒▒░░▓▓░░▒▒▓▓▒▒▒▒░░         
            ░░▒▒▒▒▒░░░░▒▒▒▒▒░░               
"""

class Ldap:
    """Helper for authentication and searches in LDAP/Active Directory."""

    # ---------- Class constants ----------

    # Attributes we collapse to scalar if they come in a list
    SCALAR_ATTRS = {
        "name",
        "sAMAccountName",
        "distinguishedName",
        "primaryGroupID",
        "objectSid",
        "displayName",
        "title",
        "department",
        "manager",
        "adminCount",
        "info",
        "description",
        "gPLink",
        "gPOptions",
        "managedBy",
        "userAccountControl",
        "lastLogonTimestamp",
        "pwdLastSet", 
        "mail",
        "userPrincipalName",
        "whenCreated",
        "whenChanged",
    }

    ALLOWED_CONTAINERS = {
        "CN=USERS",
        "CN=COMPUTERS",
        "CN=MANAGED SERVICE ACCOUNTS",
        "CN=BUILTIN",
        "CN=FOREIGNSECURITYPRINCIPALS",
    }

    # Standard attribute sets for different AD object types
    BASIC_OBJECT_ATTRS = [
        "distinguishedName",
        "description", 
        "sAMAccountName",
        "name",
        "primaryGroupID",
        "objectSid",
    ]

    USER_ATTRS = BASIC_OBJECT_ATTRS + [
        "displayName",
        "title",
        "department", 
        "manager",
        "adminCount",
        "info",
        "userAccountControl",
        "lastLogonTimestamp",
        "pwdLastSet",
        "mail",
        "userPrincipalName",
    ]

    GROUP_ATTRS = [
        "name",
        "sAMAccountName", 
        "description",
        "distinguishedName",
        "managedBy",
        "info",
    ]

    OU_ATTRS = [
        "distinguishedName",
        "name", 
        "description",
        "gPLink",
        "gPOptions",
        "managedBy",
    ]

    GPO_ATTRS = [
        "displayName",
        "description",
        "gPCFileSysPath", 
        "versionNumber",
        "distinguishedName",
        "name",
        "whenCreated",
        "whenChanged",
    ]

    DISPLAY_NAME_ATTRS = [
        "displayName",
        "name", 
        "sAMAccountName",
    ]

    # ---------- Initialization ----------

    def __init__(self, target: str, domain: str, username: str, password: str, ssl_enabled: bool = False, page_size: int = 200,) -> None:
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = ssl_enabled
        self.page_size = page_size

        self.log = logging.getLogger(__name__)
        self.base_dn = None  # Will be discovered from RootDSE after connecting
        self.conn: Optional[ldap3.Connection] = None
        
        # LDAP request counter for statistics
        self.ldap_requests = 0

    # ---------- Context manager ----------

    def __enter__(self) -> "Ldap":
        self.conn = self.connect()
        if self.conn:
            self.base_dn = self._discover_basedn(self.conn)
            if not self.base_dn:
                self.log.error("Could not discover base DN from RootDSE")
                self.close_connection(self.conn)
                self.conn = None
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close_connection(self.conn)

    # ---------- Connection management ----------

    def _discover_basedn(self, conn: ldap3.Connection) -> Optional[str]:
        """Read defaultNamingContext from RootDSE."""
        try:
            self.ldap_requests += 1
            self.log.debug("LDAP Request #%d: RootDSE discovery", self.ldap_requests)
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["defaultNamingContext"],
            )
            if conn.entries and "defaultNamingContext" in conn.entries[0]:
                return conn.entries[0]["defaultNamingContext"].value
        except LDAPException:
            self.log.debug("Could not read RootDSE", exc_info=True)
        return None

    def connect(self) -> Optional[ldap3.Connection]:
        """Try connection strategies in order until one succeeds."""
        strategies = self._get_connection_strategies()
        
        for strategy in strategies:
            try:
                result = strategy()
                if result:
                    return result
            except Exception as e:
                self._log_strategy_failure(strategy.__name__, e)
        
        self.log.error("All connection strategies failed")
        return None

    def _get_connection_strategies(self) -> List:
        """Return ordered list of connection strategies to try."""
        if self.use_ssl:
            return [
                self._try_ldaps_strict,
                self._try_ldaps_insecure, 
                self._try_ldap_plain
            ]
        else:
            return [
                self._try_ldap_plain,
                self._try_ldaps_on_strong_auth_required
            ]

    def _try_ldaps_strict(self) -> Optional[ldap3.Connection]:
        """Try LDAPS with strict certificate validation."""
        conn = self._create_connection(use_ssl=True, insecure_ssl=False, port=636)
        self.log.info("LDAPS (strict) - Login successful")
        return conn

    def _try_ldaps_insecure(self) -> Optional[ldap3.Connection]:
        """Try LDAPS without certificate validation."""
        conn = self._create_connection(use_ssl=True, insecure_ssl=True, port=636)
        self.log.info("LDAPS (insecure) - Login successful")
        return conn

    def _try_ldap_plain(self) -> Optional[ldap3.Connection]:
        """Try plain LDAP connection."""
        conn = self._create_connection(use_ssl=False, insecure_ssl=False, port=389)
        self.log.info("LDAP - Login successful")
        return conn

    def _try_ldaps_on_strong_auth_required(self) -> Optional[ldap3.Connection]:
        """Try LDAPS when strongAuthRequired is detected."""
        try:
            return self._try_ldap_plain()
        except LDAPBindError as exc:
            if self._is_stronger_auth_required(exc):
                self.log.warning("DC requires LDAP signing/sealing (strongAuthRequired). Trying LDAPS.")
                try:
                    return self._try_ldaps_strict()
                except ssl.SSLCertVerificationError:
                    self.log.warning("LDAPS (strict) failed certificate; trying insecure LDAPS.")
                    return self._try_ldaps_insecure()
            else:
                raise

    def _create_connection(self, use_ssl: bool, insecure_ssl: bool, port: int) -> ldap3.Connection:
        """Create connection with specified parameters without modifying object state."""
        
        # Create server with specified SSL settings
        tls = None
        if use_ssl:
            validate = ssl.CERT_NONE if insecure_ssl else ssl.CERT_REQUIRED
            tls = ldap3.Tls(validate=validate)
        
        server = ldap3.Server(
            host=self.target, 
            port=port, 
            use_ssl=use_ssl, 
            tls=tls, 
            get_info=ldap3.NONE, 
            connect_timeout=5
        )
        
        # Create connection
        user = f"{self.domain}\\{self.username}"
        return ldap3.Connection(
            server=server, 
            user=user, 
            password=self.password, 
            authentication=ldap3.NTLM, 
            auto_bind=True, 
            raise_exceptions=True, 
            auto_referrals=False
        )

    def _log_strategy_failure(self, strategy_name: str, exception: Exception) -> None:
        """Log strategy failure with appropriate level."""
        if isinstance(exception, ssl.SSLCertVerificationError):
            self.log.warning(f"{strategy_name} failed: Certificate verification error")
        elif isinstance(exception, LDAPBindError):
            self.log.warning(f"{strategy_name} failed: {exception}")
        else:
            self.log.debug(f"{strategy_name} failed: {exception}")

    def close_connection(self, ldap_connection: Optional[ldap3.Connection]) -> None:
        """Close the connection if active."""
        try:
            if ldap_connection and ldap_connection.bound:
                ldap_connection.unbind()
                self.log.debug("LDAP connection closed")
        except Exception:
            self.log.debug("Error closing connection", exc_info=True)

    @staticmethod
    def _is_stronger_auth_required(exc: LDAPBindError) -> bool:
        """Inspect the result dict in LDAPBindError."""
        try:
            if exc.args and isinstance(exc.args[0], dict):
                result_dict = exc.args[0]
                code = result_dict.get("result")
                desc = (result_dict.get("description") or "").lower()
                # 8 = strongAuthRequired
                return code == 8 or desc == "strongauthrequired"
        except Exception:
            pass
        return False

    # ---------- Data processing ----------

    @staticmethod
    def _filetime_to_datetime(filetime_value) -> Optional[str]:
        """Convert Windows FILETIME to readable datetime string."""
        if not filetime_value:
            return None
        
        try:
            # Convert string to int if needed
            if isinstance(filetime_value, str):
                filetime_int = int(filetime_value)
            else:
                filetime_int = int(filetime_value)
            
            # Handle special values
            if filetime_int == 0:
                return "Never"
            if filetime_int == 9223372036854775807:  # Maximum int64 value
                return "Never expires"
                
            # FILETIME epoch: January 1, 1601 00:00:00 UTC
            # Convert 100-nanosecond intervals to seconds
            seconds_since_epoch = (filetime_int - 116444736000000000) / 10000000
            
            # Convert to datetime
            dt = datetime.fromtimestamp(seconds_since_epoch, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            
        except (ValueError, OSError, OverflowError):
            return f"Invalid FILETIME: {filetime_value}"

    @staticmethod
    def _generalized_time_to_datetime(gt_value) -> Optional[str]:
        """Convert LDAP Generalized Time to readable datetime string."""
        if not gt_value:
            return None
        
        try:
            # Convert to string if needed
            gt_str = str(gt_value).strip()
            
            # Handle Generalized Time format: YYYYMMDDHHMMSS.fZ or YYYYMMDDHHMMSSZ
            
            # Remove 'Z' suffix and fractional seconds if present
            if gt_str.endswith('Z'):
                gt_str = gt_str[:-1]
            if '.' in gt_str:
                gt_str = gt_str.split('.')[0]
            
            # Parse the timestamp: YYYYMMDDHHMMSS
            if len(gt_str) == 14:
                dt = datetime.strptime(gt_str, "%Y%m%d%H%M%S")
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            else:
                return f"Invalid GT format: {gt_value}"
                
        except (ValueError, TypeError):
            return f"Invalid GeneralizedTime: {gt_value}"

    @staticmethod
    def _sid_bytes_to_str(b: bytes) -> str:
        """Convert binary SID to S-1-... format."""
        if not b or len(b) < 8:
            return ""
        revision = b[0]
        sub_count = b[1]
        authority = int.from_bytes(b[2:8], byteorder="big")
        subs = []
        offset = 8
        for _ in range(sub_count):
            if offset + 4 > len(b):
                break
            subs.append(int.from_bytes(b[offset : offset + 4], byteorder="little"))
            offset += 4
        return "S-{}-{}-{}".format(revision, authority, "-".join(str(s) for s in subs))

    def _normalize(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize attributes: convert objectSid to SDDL, timestamps to readable dates; collapse scalars."""
        out: Dict[str, Any] = {}
        for k, v in attributes.items():
            # Convert objectSid to SDDL string
            if k == "objectSid":
                if isinstance(v, (bytes, bytearray)):
                    v = self._sid_bytes_to_str(bytes(v))
                elif isinstance(v, list) and v:
                    if isinstance(v[0], (bytes, bytearray)):
                        v = self._sid_bytes_to_str(bytes(v[0]))
                    else:
                        v = v[0]
            # Convert timestamps to readable dates (different formats for different attributes)
            elif k in ("lastLogonTimestamp", "pwdLastSet"):
                # These are FILETIME values (large integers)
                if isinstance(v, list) and v:
                    v = self._filetime_to_datetime(v[0])
                else:
                    v = self._filetime_to_datetime(v)
            elif k in ("whenCreated", "whenChanged"):
                # These are Generalized Time values (YYYYMMDDHHMMSS.fZ format)
                if isinstance(v, list) and v:
                    v = self._generalized_time_to_datetime(v[0])
                else:
                    v = self._generalized_time_to_datetime(v)
            # Collapse known scalar attributes when they come as lists
            if k in self.SCALAR_ATTRS and isinstance(v, list):
                v = v[0] if v else None
            out[k] = v
        return out

    # ---------- Core LDAP operations ----------

    def search(self, ldap_connection: ldap3.Connection, ldap_filter: str, attributes: Iterable[str], search_base: Optional[str] = None, search_scope=ldap3.SUBTREE,) -> List[Dict[str, Any]]:
        """Paged searches + normalization."""
        try:
            self.ldap_requests += 1
            self.log.debug("LDAP Request #%d: Search filter=%s, attrs=%s", self.ldap_requests, ldap_filter, list(attributes))
            
            entry_generator = ldap_connection.extend.standard.paged_search(
                search_base=search_base or self.base_dn,
                search_filter=ldap_filter,
                search_scope=search_scope,
                attributes=list(attributes),
                paged_size=self.page_size,
                generator=True,
            )

            normalized_results: List[Dict[str, Any]] = []
            total_entries = 0
            for entry in entry_generator:
                if entry.get("type") != "searchResEntry":
                    continue
                normalized_entry = self._normalize(entry.get("attributes", {}))
                normalized_results.append(normalized_entry)
                total_entries += 1

            if not normalized_results:
                self.log.debug("LDAP search returned no results")
            else:
                self.log.debug("Retrieved %d objects (page_size=%d)", total_entries, self.page_size)
            return normalized_results

        except LDAPException:
            self.log.exception("Error during LDAP search")
            return []

    # ---------- Object resolution ----------

    @staticmethod
    def _looks_like_dn(value: str) -> bool:
        """Check if a string looks like a DN (Distinguished Name)."""
        v = value.strip()
        if "=" not in v or "," not in v:
            return False
        start = v.split(",", 1)[0].strip().upper()
        return start.startswith(("CN=", "OU=", "DC="))

    def get_object_by_dn(self, conn: ldap3.Connection, dn: str, attrs: Iterable[str]) -> Optional[Dict[str, Any]]:
        """Get an AD object by its Distinguished Name with specified attributes."""
        try:
            self.ldap_requests += 1
            self.log.debug("LDAP Request #%d: Search by DN=%s, attrs=%s", self.ldap_requests, dn, list(attrs))
            
            conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=list(attrs),
            )
            if not conn.entries:
                return None
            raw = {a: conn.entries[0][a].value for a in attrs if a in conn.entries[0]}
            return self._normalize(raw)
        except LDAPException:
            self.log.debug("get_object_by_dn failed for %s", dn, exc_info=True)
            return None

    def get_object_by_sid(self, conn: ldap3.Connection, sid: str) -> Optional[Dict[str, Any]]:
        """Get an AD object by searching for its SID (Security Identifier)."""
        try:
            esc_sid = ldap3.utils.conv.escape_filter_chars(sid)
            ldap_filter = f"(objectSid={esc_sid})"
            results = self.search(conn, ldap_filter, self.USER_ATTRS)
            if results:
                return results[0]
        except LDAPException as e:
            self.log.debug("LDAP error during SID search: %s", e)
        except ValueError as e:
            self.log.debug("Invalid SID format '%s': %s", sid, e)
        except Exception as e:
            self.log.debug("Unexpected error during SID search: %s", e)
        
        return None

    def get_object_by_samaccountname(self, conn: ldap3.Connection, identifier: str,) -> Optional[Dict[str, Any]]:
        """Get an AD object by searching for its sAMAccountName attribute."""
        esc_id = ldap3.utils.conv.escape_filter_chars(identifier)
        ldap_filter = f"(sAMAccountName={esc_id})"
        results = self.search(conn, ldap_filter, self.USER_ATTRS)
        return results[0] if results else None

    def resolve_object_by_identifier(self, conn: ldap3.Connection, identifier: str) -> Optional[Dict[str, Any]]:
        """Get an AD object by auto-detecting identifier type (DN, SID, sAMAccountName)."""
        ident = identifier.strip()

    # 0) DN
        if self._looks_like_dn(ident):
            obj = self.get_object_by_dn(conn, ident, self.USER_ATTRS)
            if obj:
                return obj

    # 1) SID
        if ident.upper().startswith("S-"):
            obj = self.get_object_by_sid(conn, ident)
            if obj:
                return obj

    # 2) If not a DN or SID, try sAMAccountName search
        obj = self.get_object_by_samaccountname(conn, ident)
        if obj:
            return obj

    # ---------- Group operations ----------

    def get_parent_groups_for_dn(self, conn: ldap3.Connection, dn: str) -> List[Dict[str, Any]]:
        """Return all groups (including nested) for a DN."""
        escaped_dn = ldap3.utils.conv.escape_filter_chars(dn)
        ldap_filter = f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={escaped_dn}))"
        return self.search(conn, ldap_filter, self.GROUP_ATTRS)

    def _search_group_by_sid(self, conn: ldap3.Connection, sid_sddl: str) -> Optional[Dict[str, Any]]:
        """Search a group by SID in SDDL format."""
        
        esc_sid = ldap3.utils.conv.escape_filter_chars(sid_sddl)
        results = self.search(conn, f"(&(objectClass=group)(objectSid={esc_sid}))", self.GROUP_ATTRS)
        if results:
            return results[0]

        return None

    def resolve_primary_group_by_sid(self, conn: ldap3.Connection, object_sid: str, primary_gid: str) -> Optional[Dict[str, Any]]:
        """Resolve primary group by SID (domain SID + primaryGroupID)."""
        try:
            base_sid = "-".join(object_sid.split("-")[:-1])
            primary_group_sid = f"{base_sid}-{int(primary_gid)}"
        except Exception:
            self.log.debug("Could not build primary group's SID", exc_info=True)
            return None

        obj = self._search_group_by_sid(conn, primary_group_sid)
        if obj:
            return obj
        return None

    @staticmethod
    def _normalize_dn_key(d: Dict[str, Any]) -> str:
        """Normalize DN to lowercase for use as deduplication key."""
        return (d.get("distinguishedName") or "").lower()

    def _add_parent_groups_to_collection(self, conn: ldap3.Connection, start_dn: str, collected_groups: List[Dict[str, Any]], known_groups_by_dn: Dict[str, Dict[str, Any]], ) -> None:
        """Add all parent groups for a DN to collections, avoiding duplicates."""
        parent_groups: List[Dict[str, Any]] = self.get_parent_groups_for_dn(conn, start_dn)

        for parent_group in parent_groups:
            # Get normalized DN as key for duplicate detection
            normalized_dn_key = self._normalize_dn_key(parent_group)
            
            if normalized_dn_key and normalized_dn_key not in known_groups_by_dn:
                collected_groups.append(parent_group)  # Add to ordered list
                known_groups_by_dn[normalized_dn_key] = parent_group  # Add to dedup dict

    # ---------- Organizational structure ----------

    def get_organizational_hierarchy(self, dn: str) -> List[str]:
        """
        Return the organizational hierarchy chain from the object upwards to domain root.
        Only includes OUs and containers that can have GPO links applied.
        """
        gpo_applicable_containers: List[str] = []
        current_dn_fragment = dn.strip()
        
        # Walk up the DN hierarchy, splitting on commas
        while "," in current_dn_fragment:
            
            relative_dn, remaining_dn_path = current_dn_fragment.split(",", 1)
            relative_dn_upper = relative_dn.strip().upper()
            
            # Only include OUs and specific containers that can have GPO links
            if relative_dn_upper.startswith("OU=") or relative_dn_upper in self.ALLOWED_CONTAINERS:
                gpo_applicable_containers.append(current_dn_fragment)
            
            # Move up one level in the hierarchy
            current_dn_fragment = remaining_dn_path
            
        return gpo_applicable_containers

    def get_display_name_for_dn(self, conn: ldap3.Connection, dn: str) -> Optional[str]:
        """Return a friendly name for a DN (displayName > name > sAMAccountName)."""
        obj = self.get_object_by_dn(conn, dn, self.DISPLAY_NAME_ATTRS)
        if not obj:
            return None
        return obj.get("displayName") or obj.get("name") or obj.get("sAMAccountName")

    # ---------- Group Policy Objects ----------

    @staticmethod
    def parse_gplink(gplink: Optional[str]) -> List[Dict[str, Any]]:
        """Parse gPLink attribute into a list of Group Policy Object references."""
        if not gplink:
            return []
        
        gpo_links: List[Dict[str, Any]] = []
        for gpo_reference, link_options in re.findall(r"\[LDAP://([^;]+);(\d+)\]", gplink):
            gpo_links.append({
                "gpo_reference": gpo_reference.strip(), 
                "link_options": int(link_options)
            })
        return gpo_links

    def read_gpo(self, conn: ldap3.Connection, gpo_dn: str) -> Optional[Dict[str, Any]]:
        return self.get_object_by_dn(conn, gpo_dn, self.GPO_ATTRS)

    def _gpo_dn_from_ref(self, ref: str) -> str:
        """Normalize a gPLink reference to a GPO DN."""
        if ref.upper().startswith("CN="):
            return ref
        guid = ref.strip()
        if not (guid.startswith("{") and guid.endswith("}")):
            guid = "{" + guid.strip("{}") + "}"
        return f"CN={guid},CN=Policies,CN=System,{self.base_dn}"


# ---------- Results Display ----------

class ResultsDisplay:
    """Handles formatting and display of Active Directory enumeration results."""
    
    def display_object_details(self, obj: Dict[str, Any], manager_name: Optional[str] = None) -> None:
        """Display detailed information about the target AD object."""
        print("Object:")
        
        # Basic identity
        if obj.get("sAMAccountName"):
            print(f"  sAMAccountName: {obj['sAMAccountName']}")
        if obj.get("displayName") and obj["displayName"] != obj.get("sAMAccountName"):
            print(f"  DisplayName: {obj['displayName']}")
        
        # Core attributes
        print(f"  DN: {obj.get('distinguishedName', 'N/A')}")
        print(f"  Description: {obj.get('description')}")
        
        # Optional attributes
        if obj.get("info"):
            print(f"  Notes (info): {obj['info']}")
        if obj.get("title"):
            print(f"  Title: {obj['title']}")
        if obj.get("department"):
            print(f"  Department: {obj['department']}")
        if obj.get("mail"):
            print(f"  Email: {obj['mail']}")
        if obj.get("userPrincipalName"):
            print(f"  UPN: {obj['userPrincipalName']}")
        
        # Account status and security
        if obj.get("userAccountControl") is not None:
            uac = int(obj['userAccountControl'])
            status_flags = []
            if uac & 0x0002:  # ACCOUNTDISABLE
                status_flags.append("DISABLED")
            if uac & 0x0010:  # LOCKOUT
                status_flags.append("LOCKED")
            if uac & 0x10000:  # DONT_EXPIRE_PASSWORD
                status_flags.append("PASSWORD_NEVER_EXPIRES")
            if uac & 0x0020:  # PASSWD_NOTREQD
                status_flags.append("NO_PASSWORD_REQUIRED")
            if uac & 0x400000:  # TRUSTED_FOR_DELEGATION
                status_flags.append("TRUSTED_FOR_DELEGATION")
            status_str = f"{uac}" + (f" ({', '.join(status_flags)})" if status_flags else " (NORMAL)")
            print(f"  userAccountControl: {status_str}")
        
        # Timestamps
        if obj.get("lastLogonTimestamp"):
            print(f"  Last Logon: {obj['lastLogonTimestamp']}")
        if obj.get("pwdLastSet"):
            print(f"  Password Last Set: {obj['pwdLastSet']}")
        
        # Management hierarchy
        if obj.get("manager"):
            mgr_line = obj["manager"]
            if manager_name:
                mgr_line += f"  ({manager_name})"
            print(f"  Manager: {mgr_line}")
        
        # Security attributes
        if obj.get("adminCount") is not None:
            print(f"  adminCount: {obj['adminCount']}")
        if obj.get("primaryGroupID"):
            print(f"  primaryGroupID: {obj['primaryGroupID']}")
        if obj.get("objectSid"):
            print(f"  objectSid: {obj['objectSid']}")
        
        print()

    def display_groups(self, groups: List[Dict[str, Any]]) -> None:
        """Display group membership information."""
        if not groups:
            print("Groups: (none)")
            return
        
        print("Groups (including nested and primary group if applicable):")
        for group in groups:
            group_name = group.get("sAMAccountName") or group.get("name") or "(no name)"
            print(f"  - {group_name}")
            
            # Group details
            if group.get("description"):
                print(f"      Description: {group['description']}")
            if group.get("info"):
                print(f"      Notes (info): {group['info']}")
            if group.get("managedBy"):
                print(f"      managedBy: {group['managedBy']}")
            if group.get("distinguishedName"):
                print(f"      DN: {group['distinguishedName']}")
        print()

    def display_organizational_units(self, ou_info_map: Dict[str, Dict[str, Any]], 
                                   gpo_links_per_ou: Dict[str, List[Dict[str, Any]]]) -> None:
        """Display OU/Container information with linked GPOs."""
        if not ou_info_map:
            print("OUs/Containers: (none)")
            return
        
        print("OUs/Containers (for the object and its groups, including ancestors):")
        for ou_key, ou_obj in ou_info_map.items():
            ou_dn = ou_obj.get("distinguishedName") or ou_key
            ou_name = ou_obj.get("name")
            
            # Determine container type and display name
            if ou_name:
                dn_parts = ou_dn.split(",")
                if dn_parts:
                    first_part = dn_parts[0].strip().upper()
                    if first_part.startswith("OU="):
                        container_type = "OU"
                    else:
                        container_type = "Container"
                print(f"  - {ou_name} ({container_type})")
            else:
                print(f"  - {ou_dn}")
            
            # OU details - always show DN if we have a name
            if ou_name:
                print(f"      DN: {ou_dn}")
            if ou_obj.get("description"):
                print(f"      Description: {ou_obj['description']}")
            if ou_obj.get("managedBy"):
                print(f"      Managed By: {ou_obj['managedBy']}")
            if ou_obj.get("gPOptions") is not None:
                print(f"      gPOptions: {ou_obj['gPOptions']}")
            
            # Linked GPOs
            self._display_gpo_links(gpo_links_per_ou.get(ou_key, []))
        print()

    def _display_gpo_links(self, gpo_links: List[Dict[str, Any]]) -> None:
        """Display GPO links for an OU/container."""
        if not gpo_links:
            return
        
        print(f"      GPO Links:")
        for link in gpo_links:
            gpo = link["gpo"]
            flags = link["flags"]
            gpo_name = gpo.get("displayName") or gpo.get("name") or "(no name)"
            
            # Map flag values to descriptive text
            flag_descriptions = {
                0: "Link enabled, not enforced",
                1: "Link disabled",
                2: "Link enabled and enforced (no block inheritance)",
                3: "Link disabled and enforced"
            }
            flag_description = flag_descriptions.get(flags, f"Unknown flag value: {flags}")
            
            print(f"        * {gpo_name}")
            if gpo.get("description"):
                print(f"            Description: {gpo['description']}")
            if gpo.get("gPCFileSysPath"):
                print(f"            SYSVOL Path: {gpo['gPCFileSysPath']}")
            if gpo.get("versionNumber") is not None:
                print(f"            versionNumber: {gpo['versionNumber']}")
            if gpo.get("whenCreated"):
                print(f"            Created: {gpo['whenCreated']}")
            if gpo.get("whenChanged"):
                print(f"            Last Modified: {gpo['whenChanged']}")
            if gpo.get("distinguishedName"):
                print(f"            DN: {gpo['distinguishedName']}")
            print(f"            gPLink flags: {flags} ({flag_description})")


# ---------- CLI ----------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Fast Active Directory context enumeration for newly obtained credentials. "
        )
    )
    p.add_argument("--domain", "-d", required=True, help="Domain (e.g., contoso.local)")
    p.add_argument("--user", "-u", required=True, help="Username (name only; DOMAIN\\user will be formed)")
    p.add_argument("--password", "-p", required=True, help="Password for NTLM authentication")
    p.add_argument("-dc", required=True, help="Domain Controller or IP (LDAP server)")
    p.add_argument(
        "-x",
        dest="identifier",
        required=True,
        help="Target object identifier (auto-detected): sAMAccountName (e.g., gandalf.wizard), Distinguished Name (e.g., CN=Aragorn,OU=Rangers,OU=Gondor,DC=middle,DC=earth), or SID (e.g., S-1-5-21-...)",
    )

    # Connection (minimal)
    p.add_argument("--ssl", action="store_true", help="Prefer LDAPS (port 636) with automatic fallback: strict cert validation → insecure LDAPS → plain LDAP (389)")

    # Misc
    p.add_argument("-s", action="store_true", help="Silent mode (suppress banner display)")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG-level logging")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:

    # Show banner unless silent mode is enabled
    if "-s" not in argv:
        print(BANNER)
    
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    log = logging.getLogger("sauron")

    client = Ldap(target=args.dc, domain=args.domain, username=args.user, password=args.password, ssl_enabled=args.ssl, )

    try:
        with client as c:
            if not c.conn or not c.conn.bound or not c.base_dn:
                log.error("Could not establish LDAP connection or discover base DN")
                return 2

            # 1) Get the object by identifier

            obj = c.resolve_object_by_identifier(c.conn, args.identifier)
            if not obj:
                log.error(f"No object found with identifier '{args.identifier}'")
                return 3

            object_dn = obj.get("distinguishedName")
            object_manager_dn = obj.get("manager")
            object_primary_gid = obj.get("primaryGroupID")
            object_sid = obj.get("objectSid")

            manager_name = None
            if object_manager_dn:
                try:
                    manager_name = c.get_display_name_for_dn(c.conn, object_manager_dn)
                except Exception:
                    log.debug("Could not resolve manager DN", exc_info=True)

            # 2) Get all parent groups (nested) for the object

            groups: List[Dict[str, Any]] = []  # Ordered list of all groups (for display output)
            known_groups: Dict[str, Dict[str, Any]] = {}  # DN-keyed dict for duplicate detection
            c._add_parent_groups_to_collection(c.conn, object_dn, groups, known_groups)

            # 3) Resolve primary group and collect its parent groups
            # Primary group is determined by combining object SID + primaryGroupID

            if object_primary_gid and object_sid:
                try:
                    primary_group = c.resolve_primary_group_by_sid(c.conn, str(object_sid), str(object_primary_gid))
                    
                    # Fallback to well-known groups if SID resolution fails
                    if not primary_group:
                        builtin_groups_fallback = {
                            "512": "Domain Admins",
                            "513": "Domain Users",
                            "514": "Domain Guests", 
                            "515": "Domain Computers",
                            "516": "Domain Controllers",
                            "518": "Schema Admins",
                            "519": "Enterprise Admins",
                            "520": "Group Policy Creator Owners",
                        }
                        group_name = builtin_groups_fallback.get(str(object_primary_gid))
                        if group_name:
                            # Construct fallback DN - built-in groups are typically under CN=Users
                            fallback_dn = f"CN={group_name},CN=Users,{c.base_dn}"
                            primary_group = {
                                "sAMAccountName": group_name,
                                "name": group_name,
                                "description": "",
                                "distinguishedName": fallback_dn,
                            }
                    
                    # Add primary group to collections and get its parent groups
                    if primary_group:
                        primary_group_dn_key = c._normalize_dn_key(primary_group)
                        if primary_group_dn_key and primary_group_dn_key not in known_groups:
                            groups.append(primary_group)  # Add to ordered list
                            known_groups[primary_group_dn_key] = primary_group  # Add to dedup dict
                        
                        # Also collect any groups that contain this primary group
                        primary_group_dn = primary_group.get("distinguishedName")
                        c._add_parent_groups_to_collection(c.conn, primary_group_dn, groups, known_groups)
                        
                except Exception:
                    log.debug("Could not resolve primary group", exc_info=True)

            # Sort groups by sAMAccountName (or name as fallback), case-insensitive
            def _key(x: Dict[str, Any]) -> str:
                return (x.get("sAMAccountName") or x.get("name") or "").lower()

            groups_sorted = sorted(groups, key=_key)

            # 4) Collect all unique OUs/containers in the organizational hierarchy
            # This includes the full path from object + all groups to domain root

            unique_ou_containers: Dict[str, Dict[str, Any]] = {}  # Dedup dict (lowercase DN keys)
            
            # Collect OU hierarchy for the target object itself
            for ou_dn in c.get_organizational_hierarchy(object_dn):
                unique_ou_containers[ou_dn.lower()] = {"dn": ou_dn}
            
            # Collect OU hierarchy for each group the object belongs to
            for group in groups_sorted:
                group_dn = group.get("distinguishedName")
                for ou_dn in c.get_organizational_hierarchy(group_dn):
                    unique_ou_containers[ou_dn.lower()] = {"dn": ou_dn}

            # 5) Enumerate Group Policy Objects (GPOs) linked to each OU/container
            
            ou_info_map: Dict[str, Dict[str, Any]] = {}  # OU details keyed by lowercase DN
            gpo_links_per_ou: Dict[str, List[Dict[str, Any]]] = {}  # GPO -> OU mapping with flags
            gpo_cache: Dict[str, Dict[str, Any]] = {}  # GPO object cache to avoid duplicate queries

            for ou_key, ou_entry in unique_ou_containers.items():
                ou_dn = ou_entry["dn"]
                try:
                    # Read full OU/container attributes (including gPLink)
                    ou_obj = c.get_object_by_dn(c.conn, ou_dn, c.OU_ATTRS)
                    if not ou_obj:
                        log.debug("Could not read OU/container: %s", ou_dn)
                        continue
                    ou_info_map[ou_key] = ou_obj

                    # Parse gPLink attribute to extract GPO references and flags
                    gpo_link_references = c.parse_gplink(ou_obj.get("gPLink"))
                    resolved_gpos: List[Dict[str, Any]] = []
                    
                    for gpo_ref in gpo_link_references:
                        # Convert GPO reference to full DN and resolve object
                        gpo_dn = c._gpo_dn_from_ref(gpo_ref["gpo_reference"])
                        gpo_dn_lower = gpo_dn.lower()
                        
                        # Use cache to avoid redundant LDAP queries for same GPO
                        if gpo_dn_lower not in gpo_cache:
                            gpo_object = c.read_gpo(c.conn, gpo_dn)
                            if gpo_object:
                                gpo_cache[gpo_dn_lower] = gpo_object
                        
                        cached_gpo = gpo_cache.get(gpo_dn_lower)
                        if cached_gpo:
                            resolved_gpos.append({
                                "gpo": cached_gpo,
                                "flags": gpo_ref["link_options"],  # Enforcement/inheritance flags
                            })
                    
                    gpo_links_per_ou[ou_key] = resolved_gpos
                except Exception:
                    log.debug("Failed to read OU/container %s", ou_dn, exc_info=True)

            # 6) Display enumeration results in a structured format

            formatter = ResultsDisplay()
            formatter.display_object_details(obj, manager_name)
            formatter.display_groups(groups_sorted)
            formatter.display_organizational_units(ou_info_map, gpo_links_per_ou)

            return 0

    except Exception:
        log.exception("Unexpected failure")
        return 1
    finally:
        # Show LDAP request statistics
        if client.ldap_requests > 0:
            log.info("LDAP Statistics: %d total requests made", client.ldap_requests)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
