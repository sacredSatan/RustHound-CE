use std::collections::HashMap;
use std::error::Error;
use ldap3::SearchEntry;
use regex::Regex;
use indicatif::ProgressBar;
use crate::objects::common::parse_unknown;
use crate::objects::{
    user::User,
    computer::Computer,
    group::Group,
    ou::Ou,
    container::Container,
    gpo::Gpo,
    domain::Domain,
    fsp::Fsp,
    trust::Trust,
    ntauthstore::NtAuthStore,
    aiaca::AIACA,
    rootca::RootCA,
    enterpriseca::EnterpriseCA,
    certtemplate::CertTemplate,
    inssuancepolicie::IssuancePolicie,
};
use std::convert::TryInto;

use log::{info, trace};
use crate::args::Options;
use crate::banner::progress_bar;
use crate::enums::ldaptype::*;
use crate::utils::batch::process_batch;
// use crate::modules::adcs::parser::{parse_adcs_ca,parse_adcs_template};

/// Function to get type for object by object
pub fn parse_result_type(
    common_args:            &Options, 
    result:                 Vec<SearchEntry>,
    vec_users:              &mut Vec<User>,
    vec_groups:             &mut Vec<Group>,
    vec_computers:          &mut Vec<Computer>,
    vec_ous:                &mut Vec<Ou>,
    vec_domains:            &mut Vec<Domain>,
    vec_gpos:               &mut Vec<Gpo>,
    vec_fsps:               &mut Vec<Fsp>,
    vec_containers:         &mut Vec<Container>,
    vec_trusts:             &mut Vec<Trust>,
    vec_ntauthstore:        &mut Vec<NtAuthStore>,
    vec_aiacas:             &mut Vec<AIACA>,
    vec_rootcas:            &mut Vec<RootCA>,
    vec_enterprisecas:      &mut Vec<EnterpriseCA>,
    vec_certtemplates:      &mut Vec<CertTemplate>,
    vec_issuancepolicies:   &mut Vec<IssuancePolicie>,

    dn_sid:             &mut HashMap<String, String>,
    sid_type:           &mut HashMap<String, String>,
    fqdn_sid:           &mut HashMap<String, String>,
    fqdn_ip:            &mut HashMap<String, String>,
    // adcs_templates: &mut HashMap<String, Vec<String>>,
) -> Result<(), Box<dyn Error>> {
    // Domain name
    let domain = &common_args.domain;

    // Check if batching is enabled
    let use_batching = common_args.batch_size.is_some();
    let batch_size = common_args.batch_size.unwrap_or(usize::MAX);
    
    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = result.len();
    let mut domain_sid: String = "DOMAIN_SID".to_owned();
    let mut batch_number = 1;
    let mut objects_in_batch = 0;

    info!("Starting the LDAP objects parsing...");
    if use_batching {
        info!("Batch processing enabled with batch size of {}", batch_size);
    }
    
    for entry in result {
        // Start parsing with Type matching
        let cloneresult = entry.clone();
        //println!("{:?}",&entry);
        let atype = get_type(entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_users.push(user);
                objects_in_batch += 1;
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_groups.push(group);
                objects_in_batch += 1;
            }
            Type::Computer => {
                let mut computer = Computer::new();
                computer.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    fqdn_sid,
                    fqdn_ip,
                    &domain_sid
                )?;
                vec_computers.push(computer);
                objects_in_batch += 1;
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_ous.push(ou);
                objects_in_batch += 1;
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain = domain_object.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                )?;
                domain_sid = domain_sid_from_domain;
                vec_domains.push(domain_object);
                objects_in_batch += 1;
            }
            Type::Gpo => {
                let mut  gpo = Gpo::new();
                gpo.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_gpos.push(gpo);
                objects_in_batch += 1;
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                )?;
                vec_fsps.push(security_principal);
                objects_in_batch += 1;
            }
            Type::Container => {
                let re = Regex::new(r"[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}")?;
                if re.is_match(&cloneresult.dn.to_uppercase()) 
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue
                }
                let re = Regex::new(r"CN=DOMAINUPDATES,CN=SYSTEM,")?;
                if re.is_match(&cloneresult.dn.to_uppercase()) 
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue
                }
                //trace!("Container: {}",&cloneresult.dn.to_uppercase());
                let mut container = Container::new();
                container.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_containers.push(container);
                objects_in_batch += 1;
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(
                    cloneresult,
                    domain
                )?;
                vec_trusts.push(trust);
                objects_in_batch += 1;
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_ntauthstore.push(nt_auth_store); 
                objects_in_batch += 1;
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_aiacas.push(aiaca); 
                objects_in_batch += 1;
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_rootcas.push(root_ca); 
                objects_in_batch += 1;
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_enterprisecas.push(enterprise_ca); 
                objects_in_batch += 1;
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_certtemplates.push(cert_template);
                objects_in_batch += 1;
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(
                    cloneresult,
                    domain,
                    dn_sid,
                    sid_type,
                    &domain_sid
                )?;
                vec_issuancepolicies.push(issuance_policie);
                objects_in_batch += 1;
            }
            Type::Unknown => {
                trace!("Unknown object type");
                //let result_dn = cloneresult.dn.to_uppercase();
                //let _unknown_json = parse_unknown(cloneresult, domain);
            }
        }
        // Progress Bar
        count += 1;
        pb.set_length(total as u64);
        pb.set_position(count as u64);
        progress_bar(pb.clone(), "Parsing LDAP objects".to_string(), (100 * count / total).try_into()?, "%".to_string());
        
        // Process batch if needed
        if use_batching && objects_in_batch >= batch_size {
            process_batch(
                common_args,
                vec_users,
                vec_groups,
                vec_computers,
                vec_ous,
                vec_domains,
                vec_gpos,
                vec_containers,
                vec_ntauthstore,
                vec_aiacas,
                vec_rootcas,
                vec_enterprisecas,
                vec_certtemplates,
                vec_issuancepolicies,
                batch_number,
            )?;
            
            // Reset batch counter and increment batch number
            objects_in_batch = 0;
            batch_number += 1;
        }
    }
    
    // Process any remaining objects in a final batch if batching is enabled
    if use_batching && objects_in_batch > 0 {
        process_batch(
            common_args,
            vec_users,
            vec_groups,
            vec_computers,
            vec_ous,
            vec_domains,
            vec_gpos,
            vec_containers,
            vec_ntauthstore,
            vec_aiacas,
            vec_rootcas,
            vec_enterprisecas,
            vec_certtemplates,
            vec_issuancepolicies,
            batch_number,
        )?;
    }
    
    Ok(())
}