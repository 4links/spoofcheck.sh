#!/bin/sh

set -eu

RED="\033[01;31m"    # Issues/Errors
GREEN="\033[01;32m"  # Success
YELLOW="\033[01;33m" # Warnings
BLUE="\033[01;34m"   # Information
BOLD="\033[01;01m"   # Highlight
RESET="\033[00m"     # Normal

_err() {
  msg=$1
  printf "${BOLD}[${RED}!${RESET}${BOLD}]${RESET} %s\n" "${msg}" 1>&2
}

_fatal() {
  _err "$1"
  exit 1
}

_success() {
  msg=$1
  printf "${BOLD}[${GREEN}+${RESET}${BOLD}]${RESET} %s\n" "${msg}"
}

_warn() {
  msg=$1
  printf "${BOLD}[${YELLOW}*${RESET}${BOLD}]${RESET} %s\n" "${msg}"
}

_info() {
  msg=$1
  printf "${BOLD}[${BLUE}*${RESET}${BOLD}]${RESET} %s\n" "${msg}"
}

_regex() {
  case "$#" in
  1)
    search_string=$(cat /dev/stdin)
    pattern=$1
    ;;
  2)
    search_string=$1
    pattern=$2
    ;;
  *)
    echo "invalid input" 1>&2
    ;;
  esac
  echo "${search_string}" | grep --color=never -oE "${pattern}"
}

_contains() {
  string="$1"
  substring="$2"
  case "$string" in
  *$substring*) return 0 ;;
  *) return 1 ;;
  esac
}

_get_redirect_domain() {
  spf_record=$1
  _regex "${spf_record}" "redirect=(.*)" | cut -d'=' -f2
}

check_spf_redirect_mechanisms() {
  spf_record=$1
  redirect_domain=$(_get_redirect_domain "${spf_record}")

  if [ -n "${redirect_domain}" ]; then
    _info "Processing redirect domain: ${redirect_domain}"
    is_spf_record_strong "${redirect_domain}" && return 0
  fi
  return 1
}

check_spf_include_mechanisms() {
  spf_record=$1
  for include_domain in $(_regex "${spf_record}" "include:(.*)[ $]"); do
    include_domain=${include_domain#*:}
    _info "Processing a SPF include domain: ${include_domain}"
    is_spf_record_strong "${include_domain}" && return 0
  done
  return 1
}

is_spf_redirect_record_strong() {
  spf_record=$1
  _info "Checking SPF redirect domain: $(_get_redirect_domain "${spf_record}")"

  if check_spf_redirect_mechanisms "${spf_record}"; then
    _err "Redirect mechanism is strong."
    return 0
  fi
  _warn "Redirect mechanism is not strong."
  return 1
}

are_spf_include_mechanisms_strong() {
  spf_record=$1
  _info "Checking SPF include mechanisms"

  if check_spf_include_mechanisms "${spf_record}"; then
    _err "Include mechanisms include a strong record"
    return 0
  fi
  _warn "Include mechanisms are not strong"
  return 1
}

check_spf_include_redirect() {
  spf_record=$1

  if [ -n "$(_get_redirect_domain "${spf_record}")" ]; then
    is_spf_redirect_record_strong "${spf_record}" && return 0
  fi
  are_spf_include_mechanisms_strong "${spf_record}" && return 0
  return 1
}

check_spf_all_string() {
  spf_record=$1
  spf_all_string=$(_regex "${spf_record}" ".all")

  if [ -n "${spf_all_string}" ]; then
    if echo "${spf_all_string}" | grep -q -E "[~-]all"; then
      _warn "SPF record contains an All item: ${spf_all_string}"
      return 0
    else
      _success "SPF record All item is too weak: ${spf_all_string}"
    fi
  else
    _success "SPF record has no All string"
  fi

  check_spf_include_redirect "${spf_record}" && return 0
  return 1

}

is_spf_record_strong() {
  domain=$1
  spf_record=$(dig +short "${domain}" txt | grep "spf1" | tr -d '"')

  if [ -n "${spf_record}" ]; then
    _info "Found SPF record:"
    _info "${spf_record}"

    check_spf_all_string "${spf_record}" && return 0
    check_spf_redirect_mechanisms "${spf_record}" && return 0
    check_spf_include_mechanisms "${spf_record}" && return 0
  else
    _success "${domain} has no SPF record!"
  fi
  return 1
}

_get_dmarc_record() {
  domain=$1
  dig +short "_dmarc.${domain}" txt | grep "v=DMARC" | tr -d '"'
}

_get_org_dmarc_record() {
  domain=$1
  tld=$(echo "aaa.bbb.ccc.de" | rev | cut -d '.' -f1 | rev)
  domain=$(echo "aaa.bbb.ccc.de" | rev | cut -d '.' -f2 | rev)
  _get_dmarc_record "$(_get_org_domain "${domain}")"
}

_get_org_domain() {
  domain=$1
  tld=$(echo "aaa.bbb.ccc.de" | rev | cut -d '.' -f1 | rev)
  domain=$(echo "aaa.bbb.ccc.de" | rev | cut -d '.' -f2 | rev)
  echo "${domain}.${tld}"
}

_extract_tag_from_dmarc_record() {
  dmarc_record=$1
  tag=$2
  value=$(_regex "${dmarc_record}" "(\w+)=(.*?)(?:; ?|$)" | _regex " ${tag}=(\w*);" | tr -d ';')
  echo "${value}" | cut -d'=' -f2
}

check_dmarc_extras() {
  dmarc_record=$1

  for tag in $(echo "${dmarc_record}" | grep --color=never -oE "(\w+)=(.*?)(?:; ?|$)" | tr -d ';'); do
    key=$(echo "${tag}" | cut -d'=' -f1)
    value=$(echo "${tag}" | cut -d'=' -f2)
    case ${key} in
    pct)
      [ "${value}" != "100" ] && _warn "DMARC pct is set to ${value}% - might be possible"
      ;;
    rua)
      _warn "Aggregate reports will be sent: ${value}"
      ;;
    ruf)
      _warn "Forensics reports will be sent: ${value}"
      ;;
    *) ;;

    esac
  done
}

check_dmarc_policy() {
  dmarc_record=$1
  policy=$(_extract_tag_from_dmarc_record "${dmarc_record}" "p")

  case ${policy} in
  p=reject | p=quarantine)
    _err "DMARC policy set to ${policy}"
    return 0
    ;;
  ^$)
    _success "DMARC policy set to ${policy}"
    ;;
  *)
    _success "DMARC policy set to ${policy}"
    ;;
  esac

  return 1

}

check_dmarc_org_policy() {
  domain=$1
  org_record=$(_get_org_dmarc_record "${domain}")

  if [ -n "${org_record}" ]; then
    _info "Found organizational DMARC record:"
    _info "${org_record}"

    subdomain_policy=$(_extract_tag_from_dmarc_record "${org_record}" "sp")

    if [ -n "${subdomain_policy}" ]; then
      if [ "${subdomain_policy}" = "sp=none;" ]; then
        _success "Organizational subdomain policy set to ${subdomain_policy}"
      else
        _err "Organizational subdomain policy explicitly set to ${subdomain_policy}"
        return 0
      fi
    else
      _info "No explicit organizational subdomain policy. Defaulting to organizational policy..."
      check_dmarc_policy "${org_record}" && return 0
    fi
  else
    _success "No organization DMARC record"
  fi
  return 1
}

is_dmarc_record_strong() {
  domain=$1
  dmarc_record=$(_get_dmarc_record "${domain}")

  if [ -n "${dmarc_record}" ]; then
    _info "Found DMARC record:"
    _info "${dmarc_record}"

    check_dmarc_policy "${dmarc_record}" && return 0

    check_dmarc_extras "${dmarc_record}"

  elif [ -n "$(_get_org_domain "${domain}")" ]; then
    _info 'No DMARC record found. Looking for organizational record...'
    check_dmarc_org_policy "${domain}" && return 0
  else
    _success "${domain} has no DMARC record!"
  fi
  return 1

}

_main() {
  [ $# -ne 1 ] && (_fatal "No arguments supplied." && _usage)

  domain="$1"
  _info "Checking domain: ${domain}"
  if is_spf_record_strong "${domain}" && is_dmarc_record_strong "${domain}"; then
    _sucess "Spoofing possible for $domain"
  else
    _err "Spoofing not possible for $domain"
  fi
}

_main "$@"
