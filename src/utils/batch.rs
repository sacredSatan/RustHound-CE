use std::collections::HashMap;
use std::error::Error;
use log::{info, warn};
use colored::Colorize;

use crate::args::Options;
use crate::utils::date::return_current_fulldate;
use crate::objects::{
    user::User,
    computer::Computer,
    group::Group,
    ou::Ou,
    container::Container,
    gpo::Gpo,
    domain::Domain,
    ntauthstore::NtAuthStore,
    aiaca::AIACA,
    rootca::RootCA,
    enterpriseca::EnterpriseCA,
    certtemplate::CertTemplate,
    inssuancepolicie::IssuancePolicie,
};
use crate::json::maker::common;

/// Process and write a batch of data to files, then clear the vectors
pub fn process_batch(
    common_args: &Options,
    vec_users: &mut Vec<User>,
    vec_groups: &mut Vec<Group>,
    vec_computers: &mut Vec<Computer>,
    vec_ous: &mut Vec<Ou>,
    vec_domains: &mut Vec<Domain>,
    vec_gpos: &mut Vec<Gpo>,
    vec_containers: &mut Vec<Container>,
    vec_ntauthstores: &mut Vec<NtAuthStore>,
    vec_aiacas: &mut Vec<AIACA>,
    vec_rootcas: &mut Vec<RootCA>,
    vec_enterprisecas: &mut Vec<EnterpriseCA>,
    vec_certtemplates: &mut Vec<CertTemplate>,
    vec_issuancepolicies: &mut Vec<IssuancePolicie>,
    batch_number: usize,
) -> Result<(), Box<dyn Error>> {
    // Skip if all vectors are empty
    if vec_users.is_empty() && vec_groups.is_empty() && vec_computers.is_empty() &&
       vec_ous.is_empty() && vec_domains.is_empty() && vec_gpos.is_empty() &&
       vec_containers.is_empty() && vec_ntauthstores.is_empty() && vec_aiacas.is_empty() &&
       vec_rootcas.is_empty() && vec_enterprisecas.is_empty() && vec_certtemplates.is_empty() &&
       vec_issuancepolicies.is_empty() {
        return Ok(());
    }

    info!("Processing batch {} and writing to files...", batch_number);
    
    // Current date and time
    let datetime = return_current_fulldate();
    // Domain format for filename
    let domain_format = common_args.domain.replace(".", "_");
    
    // For zip output
    let mut json_result: HashMap<String, String> = HashMap::new();
    
    // Get counts before emptying
    let users_count = vec_users.len();
    let groups_count = vec_groups.len();
    let computers_count = vec_computers.len();
    let ous_count = vec_ous.len();
    let domains_count = vec_domains.len();
    let gpos_count = vec_gpos.len();
    let containers_count = vec_containers.len();
    let ntauthstores_count = vec_ntauthstores.len();
    let aiacas_count = vec_aiacas.len();
    let rootcas_count = vec_rootcas.len();
    let enterprisecas_count = vec_enterprisecas.len();
    let certtemplates_count = vec_certtemplates.len();
    let issuancepolicies_count = vec_issuancepolicies.len();
    
    // Add batch number to filenames
    let batch_suffix = format!("_batch{}", batch_number);
    
    // Add each type to files with a batch number suffix
    if !vec_users.is_empty() {
        common::add_file(
            &datetime,
            format!("users{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_users),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_groups.is_empty() {
        common::add_file(
            &datetime,
            format!("groups{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_groups),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_computers.is_empty() {
        common::add_file(
            &datetime,
            format!("computers{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_computers),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_ous.is_empty() {
        common::add_file(
            &datetime,
            format!("ous{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_ous),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_domains.is_empty() {
        common::add_file(
            &datetime,
            format!("domains{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_domains),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_gpos.is_empty() {
        common::add_file(
            &datetime,
            format!("gpos{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_gpos),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_containers.is_empty() {
        common::add_file(
            &datetime,
            format!("containers{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_containers),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_ntauthstores.is_empty() {
        common::add_file(
            &datetime,
            format!("ntauthstores{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_ntauthstores),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_aiacas.is_empty() {
        common::add_file(
            &datetime,
            format!("aiacas{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_aiacas),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_rootcas.is_empty() {
        common::add_file(
            &datetime,
            format!("rootcas{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_rootcas),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_enterprisecas.is_empty() {
        common::add_file(
            &datetime,
            format!("enterprisecas{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_enterprisecas),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_certtemplates.is_empty() {
        common::add_file(
            &datetime,
            format!("certtemplates{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_certtemplates),
            &mut json_result,
            common_args,
        )?;
    }
    
    if !vec_issuancepolicies.is_empty() {
        common::add_file(
            &datetime,
            format!("issuancepolicies{}", batch_suffix),
            &domain_format,
            std::mem::take(vec_issuancepolicies),
            &mut json_result,
            common_args,
        )?;
    }
    
    // Create a zip file if requested
    if common_args.zip {
        common::make_a_zip(
            &datetime,
            &format!("{}{}", domain_format, batch_suffix),
            &common_args.path,
            &json_result,
        );
    }
    
    // Log summary
    let total_objects = users_count + groups_count + computers_count + ous_count + 
                        domains_count + gpos_count + containers_count + ntauthstores_count + 
                        aiacas_count + rootcas_count + enterprisecas_count + 
                        certtemplates_count + issuancepolicies_count;
    
    info!("Batch {} completed: {} objects processed and written to disk", batch_number, total_objects.to_string().bold());
    
    Ok(())
} 