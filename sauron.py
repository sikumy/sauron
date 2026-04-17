#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import re
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPStrongerAuthRequiredResult
except ImportError:
    print("Missing 'ldap3' package. Install with: pip install ldap3==2.9.1", file=sys.stderr)
    sys.exit(1)

BANNER = """                             
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


class _Colors:
    """ANSI color codes. Disabled when stdout is not a TTY or explicitly turned off."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    _NONE = ""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and sys.stdout.isatty()

    def _c(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}{self.RESET}"

    def header(self, text: str) -> str:
        return self._c(self.BOLD + self.CYAN, text)

    def label(self, text: str) -> str:
        return self._c(self.BLUE, text)

    def value(self, text: str) -> str:
        return self._c(self.WHITE, text)

    def warning(self, text: str) -> str:
        return self._c(self.BOLD + self.YELLOW, text)

    def error(self, text: str) -> str:
        return self._c(self.BOLD + self.RED, text)

    def success(self, text: str) -> str:
        return self._c(self.GREEN, text)

    def item(self, text: str) -> str:
        return self._c(self.BOLD + self.WHITE, text)

    def dim(self, text: str) -> str:
        return self._c(self.DIM, text)

    def flag(self, text: str) -> str:
        return self._c(self.MAGENTA, text)


@dataclass
class EnumerationResult:
    target: Dict[str, Any]
    manager_name: Optional[str]
    groups: List[Dict[str, Any]]
    organizational_units: Dict[str, Dict[str, Any]]
    gpo_links: Dict[str, List[Dict[str, Any]]]


class ActiveDirectoryClient:

    LDAP_PORT = 389
    LDAPS_PORT = 636
    CONNECTION_TIMEOUT_SECONDS = 5

    FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000
    FILETIME_TICKS_PER_SECOND = 10_000_000
    NEVER_EXPIRES_FILETIME = 9_223_372_036_854_775_807

    STRONG_AUTH_REQUIRED_CODE = 8
    NESTED_MEMBER_OID = "1.2.840.113556.1.4.1941"

    WELL_KNOWN_PRIMARY_GROUPS = {
        "512": "Domain Admins",
        "513": "Domain Users",
        "514": "Domain Guests",
        "515": "Domain Computers",
        "516": "Domain Controllers",
        "518": "Schema Admins",
        "519": "Enterprise Admins",
        "520": "Group Policy Creator Owners",
    }

    SCALAR_ATTRS = {
        "name", "sAMAccountName", "distinguishedName", "primaryGroupID",
        "objectSid", "displayName", "title", "department", "manager",
        "adminCount", "info", "description", "gPLink", "gPOptions",
        "managedBy", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
        "mail", "userPrincipalName", "whenCreated", "whenChanged",
    }

    GPO_APPLICABLE_CONTAINERS = {
        "CN=USERS", "CN=COMPUTERS", "CN=MANAGED SERVICE ACCOUNTS",
        "CN=BUILTIN", "CN=FOREIGNSECURITYPRINCIPALS",
    }

    BASIC_OBJECT_ATTRS = [
        "distinguishedName", "description", "sAMAccountName",
        "name", "primaryGroupID", "objectSid",
    ]

    USER_ATTRS = BASIC_OBJECT_ATTRS + [
        "displayName", "title", "department", "manager", "adminCount",
        "info", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
        "mail", "userPrincipalName",
    ]

    GROUP_ATTRS = [
        "name", "sAMAccountName", "description",
        "distinguishedName", "managedBy", "info",
    ]

    OU_ATTRS = [
        "distinguishedName", "name", "description",
        "gPLink", "gPOptions", "managedBy",
    ]

    GPO_ATTRS = [
        "displayName", "description", "gPCFileSysPath",
        "versionNumber", "distinguishedName", "name",
        "whenCreated", "whenChanged",
    ]

    DISPLAY_NAME_ATTRS = ["displayName", "name", "sAMAccountName"]

    def __init__(self, target: str, domain: str, username: str, password: str,
                 ssl_enabled: bool = False, page_size: int = 200) -> None:
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = ssl_enabled
        self.page_size = page_size
        self.log = logging.getLogger(__name__)
        self.base_dn: Optional[str] = None
        self.conn: Optional[ldap3.Connection] = None
        self.request_count = 0

    def __enter__(self) -> "ActiveDirectoryClient":
        self.conn = self._connect()
        if self.conn:
            self.base_dn = self._discover_base_dn()
            if not self.base_dn:
                self.log.error("Could not discover base DN from RootDSE")
                self._close()
                self.conn = None
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._close()

    # -- Connection management --

    def _discover_base_dn(self) -> Optional[str]:
        try:
            self._track_request("RootDSE discovery")
            self.conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["defaultNamingContext"],
            )
            if self.conn.entries and "defaultNamingContext" in self.conn.entries[0]:
                return self.conn.entries[0]["defaultNamingContext"].value
        except LDAPException:
            self.log.debug("Could not read RootDSE", exc_info=True)
        return None

    def _connect(self) -> Optional[ldap3.Connection]:
        for strategy in self._connection_strategies():
            try:
                conn = strategy()
                if conn:
                    return conn
            except (LDAPStrongerAuthRequiredResult, LDAPBindError) as e:
                self._log_strategy_failure(strategy.__name__, e)
                if self._is_strong_auth_failure(e):
                    try:
                        return self._escalate_to_ldaps()
                    except Exception as fallback_e:
                        self._log_strategy_failure("ldaps_escalation", fallback_e)
            except Exception as e:
                self._log_strategy_failure(strategy.__name__, e)

        self.log.error("All connection strategies failed")
        return None

    def _connection_strategies(self) -> List:
        if self.use_ssl:
            return [self._connect_ldaps_strict, self._connect_ldaps_insecure, self._connect_ldap_plain]
        return [self._connect_ldap_plain]

    def _connect_ldaps_strict(self) -> ldap3.Connection:
        conn = self._build_connection(use_ssl=True, insecure_ssl=False, port=self.LDAPS_PORT)
        self.log.info("LDAPS (strict) - Login successful")
        return conn

    def _connect_ldaps_insecure(self) -> ldap3.Connection:
        conn = self._build_connection(use_ssl=True, insecure_ssl=True, port=self.LDAPS_PORT)
        self.log.info("LDAPS (insecure) - Login successful")
        return conn

    def _connect_ldap_plain(self) -> ldap3.Connection:
        conn = self._build_connection(use_ssl=False, insecure_ssl=False, port=self.LDAP_PORT)
        self.log.info("LDAP - Login successful")
        return conn

    def _escalate_to_ldaps(self) -> Optional[ldap3.Connection]:
        self.log.warning("DC requires LDAP signing/sealing (strongAuthRequired). Trying LDAPS.")
        try:
            return self._connect_ldaps_strict()
        except ssl.SSLCertVerificationError:
            self.log.warning("LDAPS (strict) failed certificate; trying insecure LDAPS.")
            return self._connect_ldaps_insecure()

    def _build_connection(self, use_ssl: bool, insecure_ssl: bool, port: int) -> ldap3.Connection:
        tls = None
        if use_ssl:
            validate = ssl.CERT_NONE if insecure_ssl else ssl.CERT_REQUIRED
            tls = ldap3.Tls(validate=validate, version=ssl.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')

        server = ldap3.Server(
            host=self.target, port=port, use_ssl=use_ssl, tls=tls,
            get_info=ldap3.NONE, connect_timeout=self.CONNECTION_TIMEOUT_SECONDS,
        )

        if use_ssl:
            user = f"{self.username}@{self.domain}"
            auth_method = ldap3.SIMPLE
        else:
            user = f"{self.domain}\\{self.username}"
            auth_method = ldap3.NTLM

        return ldap3.Connection(
            server=server, user=user, password=self.password,
            authentication=auth_method, auto_bind=True,
            raise_exceptions=True, auto_referrals=False,
        )

    def _is_strong_auth_failure(self, exc: Exception) -> bool:
        if self.use_ssl:
            return False
        if isinstance(exc, LDAPStrongerAuthRequiredResult):
            return True
        if isinstance(exc, LDAPBindError):
            return self._has_strong_auth_error_code(exc)
        return False

    @staticmethod
    def _has_strong_auth_error_code(exc: LDAPBindError) -> bool:
        try:
            if exc.args and isinstance(exc.args[0], dict):
                result_dict = exc.args[0]
                code = result_dict.get("result")
                desc = (result_dict.get("description") or "").lower()
                return code == ActiveDirectoryClient.STRONG_AUTH_REQUIRED_CODE or desc == "strongauthrequired"
        except Exception:
            pass
        return False

    def _log_strategy_failure(self, strategy_name: str, exception: Exception) -> None:
        if isinstance(exception, ssl.SSLCertVerificationError):
            self.log.warning(f"{strategy_name} failed: Certificate verification error")
        elif isinstance(exception, LDAPBindError):
            self.log.warning(f"{strategy_name} failed: {exception}")
        else:
            self.log.debug(f"{strategy_name} failed: {exception}")

    def _close(self) -> None:
        try:
            if self.conn and self.conn.bound:
                self.conn.unbind()
                self.log.debug("LDAP connection closed")
        except Exception:
            self.log.debug("Error closing connection", exc_info=True)

    def _track_request(self, description: str) -> None:
        self.request_count += 1
        self.log.debug("LDAP Request #%d: %s", self.request_count, description)

    # -- Data normalization --

    @staticmethod
    def _filetime_to_datetime(filetime_value) -> Optional[str]:
        if not filetime_value:
            return None
        try:
            filetime_int = int(filetime_value)
            if filetime_int == 0:
                return "Never"
            if filetime_int == ActiveDirectoryClient.NEVER_EXPIRES_FILETIME:
                return "Never expires"
            seconds = (filetime_int - ActiveDirectoryClient.FILETIME_EPOCH_OFFSET) / ActiveDirectoryClient.FILETIME_TICKS_PER_SECOND
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError, OverflowError):
            return f"Invalid FILETIME: {filetime_value}"

    @staticmethod
    def _generalized_time_to_datetime(gt_value) -> Optional[str]:
        if not gt_value:
            return None
        try:
            gt_str = str(gt_value).strip()
            if gt_str.endswith('Z'):
                gt_str = gt_str[:-1]
            if '.' in gt_str:
                gt_str = gt_str.split('.')[0]
            if len(gt_str) == 14:
                dt = datetime.strptime(gt_str, "%Y%m%d%H%M%S")
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            return f"Invalid GT format: {gt_value}"
        except (ValueError, TypeError):
            return f"Invalid GeneralizedTime: {gt_value}"

    @staticmethod
    def _sid_bytes_to_str(b: bytes) -> str:
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
            subs.append(int.from_bytes(b[offset:offset + 4], byteorder="little"))
            offset += 4
        return f"S-{revision}-{authority}-{'-'.join(str(s) for s in subs)}"

    @classmethod
    def _normalize_sid(cls, value):
        if isinstance(value, (bytes, bytearray)):
            return cls._sid_bytes_to_str(bytes(value))
        if isinstance(value, list) and value:
            if isinstance(value[0], (bytes, bytearray)):
                return cls._sid_bytes_to_str(bytes(value[0]))
            return value[0]
        return value

    def _normalize(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in attributes.items():
            if key == "objectSid":
                value = self._normalize_sid(value)
            elif key in ("lastLogonTimestamp", "pwdLastSet"):
                value = self._filetime_to_datetime(value[0] if isinstance(value, list) and value else value)
            elif key in ("whenCreated", "whenChanged"):
                value = self._generalized_time_to_datetime(value[0] if isinstance(value, list) and value else value)
            if key in self.SCALAR_ATTRS and isinstance(value, list):
                value = value[0] if value else None
            out[key] = value
        return out

    # -- Core LDAP operations --

    def search(self, ldap_filter: str, attributes: Iterable[str],
               search_base: Optional[str] = None, search_scope=ldap3.SUBTREE) -> List[Dict[str, Any]]:
        try:
            self._track_request(f"Search filter={ldap_filter}, attrs={list(attributes)}")
            entry_generator = self.conn.extend.standard.paged_search(
                search_base=search_base or self.base_dn,
                search_filter=ldap_filter,
                search_scope=search_scope,
                attributes=list(attributes),
                paged_size=self.page_size,
                generator=True,
            )

            results: List[Dict[str, Any]] = []
            for entry in entry_generator:
                if entry.get("type") != "searchResEntry":
                    continue
                results.append(self._normalize(entry.get("attributes", {})))

            if results:
                self.log.debug("Retrieved %d objects (page_size=%d)", len(results), self.page_size)
            else:
                self.log.debug("LDAP search returned no results")
            return results
        except LDAPException:
            self.log.exception("Error during LDAP search")
            return []

    def find_by_dn(self, dn: str, attrs: Iterable[str]) -> Optional[Dict[str, Any]]:
        try:
            self._track_request(f"Search by DN={dn}, attrs={list(attrs)}")
            self.conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=list(attrs),
            )
            if not self.conn.entries:
                return None
            raw = {a: self.conn.entries[0][a].value for a in attrs if a in self.conn.entries[0]}
            return self._normalize(raw)
        except LDAPException:
            self.log.debug("find_by_dn failed for %s", dn, exc_info=True)
            return None

    # -- Object resolution --

    def find_by_sid(self, sid: str) -> Optional[Dict[str, Any]]:
        try:
            escaped = ldap3.utils.conv.escape_filter_chars(sid)
            results = self.search(f"(objectSid={escaped})", self.USER_ATTRS)
            if results:
                return results[0]
        except LDAPException as e:
            self.log.debug("LDAP error during SID search: %s", e)
        except ValueError as e:
            self.log.debug("Invalid SID format '%s': %s", sid, e)
        except Exception as e:
            self.log.debug("Unexpected error during SID search: %s", e)
        return None

    def find_by_samaccountname(self, name: str) -> Optional[Dict[str, Any]]:
        escaped = ldap3.utils.conv.escape_filter_chars(name)
        results = self.search(f"(sAMAccountName={escaped})", self.USER_ATTRS)
        return results[0] if results else None

    def resolve_object(self, identifier: str) -> Optional[Dict[str, Any]]:
        ident = identifier.strip()

        if self._looks_like_dn(ident):
            obj = self.find_by_dn(ident, self.USER_ATTRS)
            if obj:
                return obj

        if ident.upper().startswith("S-"):
            obj = self.find_by_sid(ident)
            if obj:
                return obj

        return self.find_by_samaccountname(ident)

    @staticmethod
    def _looks_like_dn(value: str) -> bool:
        v = value.strip()
        if "=" not in v or "," not in v:
            return False
        first_rdn = v.split(",", 1)[0].strip().upper()
        return first_rdn.startswith(("CN=", "OU=", "DC="))

    # -- Group operations --

    def find_parent_groups(self, dn: str) -> List[Dict[str, Any]]:
        escaped = ldap3.utils.conv.escape_filter_chars(dn)
        ldap_filter = f"(&(objectClass=group)(member:{self.NESTED_MEMBER_OID}:={escaped}))"
        return self.search(ldap_filter, self.GROUP_ATTRS)

    def find_group_by_sid(self, sid: str) -> Optional[Dict[str, Any]]:
        escaped = ldap3.utils.conv.escape_filter_chars(sid)
        results = self.search(f"(&(objectClass=group)(objectSid={escaped}))", self.GROUP_ATTRS)
        return results[0] if results else None

    def resolve_primary_group(self, object_sid: str, primary_gid: str) -> Optional[Dict[str, Any]]:
        try:
            domain_sid = "-".join(object_sid.split("-")[:-1])
            primary_group_sid = f"{domain_sid}-{int(primary_gid)}"
        except Exception:
            self.log.debug("Could not build primary group SID", exc_info=True)
            return None
        return self.find_group_by_sid(primary_group_sid)

    @staticmethod
    def _dn_key(obj: Dict[str, Any]) -> str:
        return (obj.get("distinguishedName") or "").lower()

    # -- Organizational hierarchy --

    def get_ou_hierarchy(self, dn: str) -> List[str]:
        containers: List[str] = []
        fragment = dn.strip()
        while "," in fragment:
            rdn, remaining = fragment.split(",", 1)
            rdn_upper = rdn.strip().upper()
            if rdn_upper.startswith("OU=") or rdn_upper in self.GPO_APPLICABLE_CONTAINERS:
                containers.append(fragment)
            fragment = remaining
        return containers

    def resolve_display_name(self, dn: str) -> Optional[str]:
        obj = self.find_by_dn(dn, self.DISPLAY_NAME_ATTRS)
        if not obj:
            return None
        return obj.get("displayName") or obj.get("name") or obj.get("sAMAccountName")

    # -- Group Policy Objects --

    @staticmethod
    def parse_gplink(gplink: Optional[str]) -> List[Dict[str, Any]]:
        if not gplink:
            return []
        return [
            {"gpo_reference": ref.strip(), "link_options": int(opts)}
            for ref, opts in re.findall(r"\[LDAP://([^;]+);(\d+)\]", gplink)
        ]

    def read_gpo(self, gpo_dn: str) -> Optional[Dict[str, Any]]:
        return self.find_by_dn(gpo_dn, self.GPO_ATTRS)

    def _gpo_dn_from_ref(self, ref: str) -> str:
        if ref.upper().startswith("CN="):
            return ref
        guid = ref.strip()
        if not (guid.startswith("{") and guid.endswith("}")):
            guid = "{" + guid.strip("{}") + "}"
        return f"CN={guid},CN=Policies,CN=System,{self.base_dn}"

    # -- Enumeration orchestration --

    def enumerate(self, identifier: str) -> Optional[EnumerationResult]:
        obj = self.resolve_object(identifier)
        if not obj:
            return None

        object_dn = obj.get("distinguishedName")
        manager_name = self._resolve_manager_name(obj.get("manager"))
        groups = self._collect_all_groups(object_dn, obj.get("objectSid"), obj.get("primaryGroupID"))
        groups_sorted = sorted(groups, key=lambda g: (g.get("sAMAccountName") or g.get("name") or "").lower())
        ou_info, gpo_links = self._collect_ous_and_gpos(object_dn, groups_sorted)

        return EnumerationResult(
            target=obj,
            manager_name=manager_name,
            groups=groups_sorted,
            organizational_units=ou_info,
            gpo_links=gpo_links,
        )

    def _resolve_manager_name(self, manager_dn: Optional[str]) -> Optional[str]:
        if not manager_dn:
            return None
        try:
            return self.resolve_display_name(manager_dn)
        except Exception:
            self.log.debug("Could not resolve manager DN", exc_info=True)
            return None

    def _collect_all_groups(self, object_dn: str, object_sid: Optional[str],
                            primary_gid: Optional[str]) -> List[Dict[str, Any]]:
        groups: List[Dict[str, Any]] = []
        known: Dict[str, Dict[str, Any]] = {}

        def _add_unique(new_groups: List[Dict[str, Any]]) -> None:
            for group in new_groups:
                key = self._dn_key(group)
                if key and key not in known:
                    groups.append(group)
                    known[key] = group

        _add_unique(self.find_parent_groups(object_dn))

        if primary_gid and object_sid:
            try:
                primary = self.resolve_primary_group(str(object_sid), str(primary_gid))
                if not primary:
                    primary = self._build_well_known_group_fallback(str(primary_gid))
                if primary:
                    _add_unique([primary])
                    primary_dn = primary.get("distinguishedName")
                    if primary_dn:
                        _add_unique(self.find_parent_groups(primary_dn))
            except Exception:
                self.log.debug("Could not resolve primary group", exc_info=True)

        return groups

    def _build_well_known_group_fallback(self, primary_gid: str) -> Optional[Dict[str, Any]]:
        group_name = self.WELL_KNOWN_PRIMARY_GROUPS.get(primary_gid)
        if not group_name:
            return None
        return {
            "sAMAccountName": group_name,
            "name": group_name,
            "description": "",
            "distinguishedName": f"CN={group_name},CN=Users,{self.base_dn}",
        }

    def _collect_ous_and_gpos(self, object_dn: str,
                              groups: List[Dict[str, Any]]) -> tuple:
        unique_ou_dns: Dict[str, str] = {}

        for ou_dn in self.get_ou_hierarchy(object_dn):
            unique_ou_dns.setdefault(ou_dn.lower(), ou_dn)

        for group in groups:
            group_dn = group.get("distinguishedName")
            if group_dn:
                for ou_dn in self.get_ou_hierarchy(group_dn):
                    unique_ou_dns.setdefault(ou_dn.lower(), ou_dn)

        ou_info: Dict[str, Dict[str, Any]] = {}
        gpo_links: Dict[str, List[Dict[str, Any]]] = {}
        gpo_cache: Dict[str, Dict[str, Any]] = {}

        for ou_key, ou_dn in unique_ou_dns.items():
            try:
                ou_obj = self.find_by_dn(ou_dn, self.OU_ATTRS)
                if not ou_obj:
                    self.log.debug("Could not read OU/container: %s", ou_dn)
                    continue
                ou_info[ou_key] = ou_obj
                gpo_links[ou_key] = self._resolve_gpo_links(ou_obj, gpo_cache)
            except Exception:
                self.log.debug("Failed to read OU/container %s", ou_dn, exc_info=True)

        return ou_info, gpo_links

    def _resolve_gpo_links(self, ou_obj: Dict[str, Any],
                           cache: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        resolved = []
        for ref in self.parse_gplink(ou_obj.get("gPLink")):
            gpo_dn = self._gpo_dn_from_ref(ref["gpo_reference"])
            gpo_dn_lower = gpo_dn.lower()

            if gpo_dn_lower not in cache:
                gpo = self.read_gpo(gpo_dn)
                if gpo:
                    cache[gpo_dn_lower] = gpo

            cached = cache.get(gpo_dn_lower)
            if cached:
                resolved.append({"gpo": cached, "flags": ref["link_options"]})
        return resolved


# ---------- Results Display ----------

class ResultsDisplay:
    """Handles formatting and display of Active Directory enumeration results."""

    def __init__(self, color: bool = True) -> None:
        self.c = _Colors(enabled=color)

    UAC_FLAGS = [
        (0x00000001, "SCRIPT", None),
        (0x00000002, "ACCOUNTDISABLE", "Account is DISABLED"),
        (0x00000008, "HOMEDIR_REQUIRED", None),
        (0x00000010, "LOCKOUT", "Account is LOCKED OUT"),
        (0x00000020, "PASSWD_NOTREQD", "No password required to logon"),
        (0x00000040, "PASSWD_CANT_CHANGE", None),
        (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED", "Reversible encryption for password storage"),
        (0x00000100, "TEMP_DUPLICATE_ACCOUNT", None),
        (0x00000200, "NORMAL_ACCOUNT", None),
        (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT", None),
        (0x00001000, "WORKSTATION_TRUST_ACCOUNT", None),
        (0x00002000, "SERVER_TRUST_ACCOUNT", "Domain Controller account"),
        (0x00010000, "DONT_EXPIRE_PASSWORD", "Password never expires"),
        (0x00020000, "MNS_LOGON_ACCOUNT", None),
        (0x00040000, "SMARTCARD_REQUIRED", "Smart card required for interactive logon"),
        (0x00080000, "TRUSTED_FOR_DELEGATION", "Unconstrained Kerberos delegation enabled"),
        (0x00100000, "NOT_DELEGATED", "Account is sensitive and cannot be delegated"),
        (0x00200000, "USE_DES_KEY_ONLY", "Only DES encryption types for Kerberos"),
        (0x00400000, "DONT_REQUIRE_PREAUTH", "AS-REP Roastable (no Kerberos pre-auth)"),
        (0x00800000, "PASSWORD_EXPIRED", "Password has expired"),
        (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION", "Constrained delegation with protocol transition (S4U2Self)"),
        (0x02000000, "NO_AUTH_DATA_REQUIRED", None),
        (0x04000000, "PARTIAL_SECRETS_ACCOUNT", "Read-Only Domain Controller (RODC)"),
    ]

    GPO_LINK_FLAGS = {
        0: "Link enabled, not enforced",
        1: "Link disabled",
        2: "Link enabled and enforced (no block inheritance)",
        3: "Link disabled and enforced",
    }

    def display(self, result: EnumerationResult) -> None:
        self._display_object(result.target, result.manager_name)
        self._display_groups(result.groups)
        self._display_organizational_units(result.organizational_units, result.gpo_links)

    def _kv(self, label: str, value: str, indent: str = "  ") -> str:
        return f"{indent}{self.c.label(label + ':')} {self.c.value(str(value))}"

    def _display_object(self, obj: Dict[str, Any], manager_name: Optional[str] = None) -> None:
        print(self.c.header("Object:"))

        if obj.get("sAMAccountName"):
            print(self._kv("sAMAccountName", obj["sAMAccountName"]))
        if obj.get("displayName") and obj["displayName"] != obj.get("sAMAccountName"):
            print(self._kv("DisplayName", obj["displayName"]))

        print(self._kv("DN", obj.get("distinguishedName", "N/A")))
        print(self._kv("Description", str(obj.get("description"))))

        optional_attrs = [
            ("info", "Notes (info)"),
            ("title", "Title"),
            ("department", "Department"),
            ("mail", "Email"),
            ("userPrincipalName", "UPN"),
        ]
        for attr, label in optional_attrs:
            if obj.get(attr):
                print(self._kv(label, obj[attr]))

        self._display_uac(obj)

        if obj.get("lastLogonTimestamp"):
            print(self._kv("Last Logon", obj["lastLogonTimestamp"]))
        if obj.get("pwdLastSet"):
            print(self._kv("Password Last Set", obj["pwdLastSet"]))

        if obj.get("manager"):
            mgr_line = obj["manager"]
            if manager_name:
                mgr_line += f"  ({self.c.success(manager_name)})"
            print(self._kv("Manager", mgr_line))

        if obj.get("adminCount") is not None:
            print(self._kv("adminCount", str(obj["adminCount"])))
        if obj.get("primaryGroupID"):
            print(self._kv("primaryGroupID", str(obj["primaryGroupID"])))
        if obj.get("objectSid"):
            print(self._kv("objectSid", str(obj["objectSid"])))

        print()

    def _display_uac(self, obj: Dict[str, Any]) -> None:
        if obj.get("userAccountControl") is None:
            return
        uac = int(obj["userAccountControl"])
        active_flags = []
        security_notes = []
        for bit, flag_name, note in self.UAC_FLAGS:
            if uac & bit:
                active_flags.append(flag_name)
                if note:
                    security_notes.append(note)
        flags_str = ", ".join(self.c.flag(f) for f in active_flags) if active_flags else "NONE"
        print(f"  {self.c.label('userAccountControl:')} {self.c.value(str(uac))} ({flags_str})")
        for note in security_notes:
            print(f"    {self.c.warning('[!] ' + note)}")

    def _display_groups(self, groups: List[Dict[str, Any]]) -> None:
        if not groups:
            print(self.c.header("Groups:") + " (none)")
            return

        print(self.c.header("Groups (including nested and primary group if applicable):"))
        for group in groups:
            group_name = group.get("sAMAccountName") or group.get("name") or "(no name)"
            print(f"  - {self.c.item(group_name)}")
            if group.get("description"):
                print(self._kv("Description", group["description"], "      "))
            if group.get("info"):
                print(self._kv("Notes (info)", group["info"], "      "))
            if group.get("managedBy"):
                print(self._kv("managedBy", group["managedBy"], "      "))
            if group.get("distinguishedName"):
                print(f"      {self.c.label('DN:')} {self.c.dim(group['distinguishedName'])}")
        print()

    def _display_organizational_units(self, ou_info_map: Dict[str, Dict[str, Any]],
                                      gpo_links_per_ou: Dict[str, List[Dict[str, Any]]]) -> None:
        if not ou_info_map:
            print(self.c.header("OUs/Containers:") + " (none)")
            return

        print(self.c.header("OUs/Containers (for the object and its groups, including ancestors):"))
        for ou_key, ou_obj in ou_info_map.items():
            ou_dn = ou_obj.get("distinguishedName") or ou_key
            ou_name = ou_obj.get("name")

            if ou_name:
                first_part = ou_dn.split(",")[0].strip().upper()
                container_type = "OU" if first_part.startswith("OU=") else "Container"
                print(f"  - {self.c.item(ou_name)} {self.c.dim('(' + container_type + ')')}")
            else:
                print(f"  - {self.c.item(ou_dn)}")

            if ou_name:
                print(f"      {self.c.label('DN:')} {self.c.dim(ou_dn)}")
            if ou_obj.get("description"):
                print(self._kv("Description", ou_obj["description"], "      "))
            if ou_obj.get("managedBy"):
                print(self._kv("Managed By", ou_obj["managedBy"], "      "))
            if ou_obj.get("gPOptions") is not None:
                print(self._kv("gPOptions", str(ou_obj["gPOptions"]), "      "))

            self._display_gpo_links(gpo_links_per_ou.get(ou_key, []))
        print()

    def _display_gpo_links(self, gpo_links: List[Dict[str, Any]]) -> None:
        if not gpo_links:
            return

        print(f"      {self.c.label('GPO Links:')}")
        for link in gpo_links:
            gpo = link["gpo"]
            flags = link["flags"]
            gpo_name = gpo.get("displayName") or gpo.get("name") or "(no name)"
            flag_description = self.GPO_LINK_FLAGS.get(flags, f"Unknown flag value: {flags}")

            print(f"        * {self.c.item(gpo_name)}")
            if gpo.get("description"):
                print(self._kv("Description", gpo["description"], "            "))
            if gpo.get("gPCFileSysPath"):
                print(self._kv("SYSVOL Path", gpo["gPCFileSysPath"], "            "))
            if gpo.get("versionNumber") is not None:
                print(self._kv("versionNumber", str(gpo["versionNumber"]), "            "))
            if gpo.get("whenCreated"):
                print(self._kv("Created", gpo["whenCreated"], "            "))
            if gpo.get("whenChanged"):
                print(self._kv("Last Modified", gpo["whenChanged"], "            "))
            if gpo.get("distinguishedName"):
                print(f"            {self.c.label('DN:')} {self.c.dim(gpo['distinguishedName'])}")
            print(f"            {self.c.label('gPLink flags:')} {self.c.flag(str(flags))} ({flag_description})")


# ---------- CLI ----------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fast Active Directory context enumeration for newly obtained credentials.",
    )
    p.add_argument("--domain", "-d", required=True, help="Domain (e.g., contoso.local)")
    p.add_argument("--user", "-u", required=True, help="Username (name only; DOMAIN\\user will be formed)")
    p.add_argument("--password", "-p", required=True, help="Password for NTLM authentication")
    p.add_argument("-dc", required=True, help="Domain Controller or IP (LDAP server)")
    p.add_argument(
        "-x",
        dest="identifier",
        required=True,
        help="Target object identifier (auto-detected): sAMAccountName, Distinguished Name, or SID",
    )
    p.add_argument("--ssl", action="store_true", help="Prefer LDAPS (port 636) with automatic fallback")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("-v", action="store_true", help="Verbose mode (banner display)")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG-level logging")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    if "-v" in argv:
        print(BANNER)

    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    log = logging.getLogger("sauron")

    client = ActiveDirectoryClient(
        target=args.dc,
        domain=args.domain,
        username=args.user,
        password=args.password,
        ssl_enabled=args.ssl,
    )

    try:
        with client as c:
            if not c.conn or not c.conn.bound or not c.base_dn:
                log.error("Could not establish LDAP connection or discover base DN")
                return 2

            result = c.enumerate(args.identifier)
            if result is None:
                log.error("No object found with identifier '%s'", args.identifier)
                return 3

            ResultsDisplay(color=not args.no_color).display(result)
            return 0

    except Exception:
        log.exception("Unexpected failure")
        return 1
    finally:
        if client.request_count > 0:
            log.info("LDAP Statistics: %d total requests made", client.request_count)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
