use std::collections::HashMap;
use std::error::Error;
use log::{info, warn, debug};
use colored::Colorize;
use std::mem;

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
    trust::Trust,
    common::LdapObject,
};
use crate::json::maker::common;

/// Get a rough estimate of memory usage by adding up the vector capacities
fn estimate_memory_usage(
    vec_users: &Vec<User>,
    vec_groups: &Vec<Group>,
    vec_computers: &Vec<Computer>,
    vec_ous: &Vec<Ou>,
    vec_domains: &Vec<Domain>,
    vec_gpos: &Vec<Gpo>,
    vec_containers: &Vec<Container>,
    vec_ntauthstores: &Vec<NtAuthStore>,
    vec_aiacas: &Vec<AIACA>,
    vec_rootcas: &Vec<RootCA>,
    vec_enterprisecas: &Vec<EnterpriseCA>,
    vec_certtemplates: &Vec<CertTemplate>,
    vec_issuancepolicies: &Vec<IssuancePolicie>,
) -> usize {
    // This is a rough estimate using the vector capacities and an approximation of object sizes
    let user_size = std::mem::size_of::<User>() * vec_users.len();
    let group_size = std::mem::size_of::<Group>() * vec_groups.len();
    let computer_size = std::mem::size_of::<Computer>() * vec_computers.len();
    let ou_size = std::mem::size_of::<Ou>() * vec_ous.len();
    let domain_size = std::mem::size_of::<Domain>() * vec_domains.len();
    let gpo_size = std::mem::size_of::<Gpo>() * vec_gpos.len();
    let container_size = std::mem::size_of::<Container>() * vec_containers.len();
    let ntauthstore_size = std::mem::size_of::<NtAuthStore>() * vec_ntauthstores.len();
    let aiaca_size = std::mem::size_of::<AIACA>() * vec_aiacas.len();
    let rootca_size = std::mem::size_of::<RootCA>() * vec_rootcas.len();
    let enterpriseca_size = std::mem::size_of::<EnterpriseCA>() * vec_enterprisecas.len();
    let certtemplate_size = std::mem::size_of::<CertTemplate>() * vec_certtemplates.len();
    let issuancepolicy_size = std::mem::size_of::<IssuancePolicie>() * vec_issuancepolicies.len();
    
    user_size + group_size + computer_size + ou_size + domain_size + 
    gpo_size + container_size + ntauthstore_size + aiaca_size + 
    rootca_size + enterpriseca_size + certtemplate_size + issuancepolicy_size
}

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
    
    // Calculate total objects and estimated memory
    let total_objects = users_count + groups_count + computers_count + ous_count + 
                        domains_count + gpos_count + containers_count + ntauthstores_count + 
                        aiacas_count + rootcas_count + enterprisecas_count + 
                        certtemplates_count + issuancepolicies_count;
    
    let memory_before = estimate_memory_usage(
        vec_users, vec_groups, vec_computers, vec_ous, vec_domains, vec_gpos, 
        vec_containers, vec_ntauthstores, vec_aiacas, vec_rootcas, 
        vec_enterprisecas, vec_certtemplates, vec_issuancepolicies
    );
    
    // Log detailed object counts
    info!("---------- Batch {} Summary ----------", batch_number);
    info!("Total objects: {}", total_objects.to_string().bold());
    debug!("Users: {}", users_count);
    debug!("Groups: {}", groups_count);
    debug!("Computers: {}", computers_count);
    debug!("OUs: {}", ous_count);
    debug!("Domains: {}", domains_count);
    debug!("GPOs: {}", gpos_count);
    debug!("Containers: {}", containers_count);
    debug!("NtAuthStores: {}", ntauthstores_count);
    debug!("AIACAs: {}", aiacas_count);
    debug!("RootCAs: {}", rootcas_count);
    debug!("EnterpriseCAs: {}", enterprisecas_count);
    debug!("CertTemplates: {}", certtemplates_count);
    debug!("IssuancePolicies: {}", issuancepolicies_count);
    info!("Estimated memory usage: ~{} MB", (memory_before / 1024 / 1024).to_string().bold());
    
    // Current date and time
    let datetime = return_current_fulldate();
    // Domain format for filename
    let domain_format = common_args.domain.replace(".", "_");
    
    // For zip output
    let mut json_result: HashMap<String, String> = HashMap::new();
    
    // Add batch number to filenames
    let batch_suffix = format!("_batch{}", batch_number);
    
    // Add each type to files with a batch number suffix
    if !vec_users.is_empty() {
        info!("Writing {} users to file", users_count);
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
        info!("Writing {} groups to file", groups_count);
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
        info!("Writing {} computers to file", computers_count);
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
        info!("Writing {} OUs to file", ous_count);
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
        info!("Writing {} domains to file", domains_count);
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
        info!("Writing {} GPOs to file", gpos_count);
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
        info!("Writing {} containers to file", containers_count);
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
        info!("Writing {} NtAuthStores to file", ntauthstores_count);
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
        info!("Writing {} AIACAs to file", aiacas_count);
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
        info!("Writing {} RootCAs to file", rootcas_count);
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
        info!("Writing {} EnterpriseCAs to file", enterprisecas_count);
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
        info!("Writing {} CertTemplates to file", certtemplates_count);
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
        info!("Writing {} IssuancePolicies to file", issuancepolicies_count);
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
        info!("Creating zip archive for batch {}", batch_number);
        common::make_a_zip(
            &datetime,
            &format!("{}{}", domain_format, batch_suffix),
            &common_args.path,
            &json_result,
        );
    }
    
    // Calculate memory after processing
    let memory_after = estimate_memory_usage(
        vec_users, vec_groups, vec_computers, vec_ous, vec_domains, vec_gpos, 
        vec_containers, vec_ntauthstores, vec_aiacas, vec_rootcas, 
        vec_enterprisecas, vec_certtemplates, vec_issuancepolicies
    );
    
    // Memory usage should be near zero after taking the vectors
    info!("Estimated memory freed: ~{} MB", ((memory_before - memory_after) / 1024 / 1024).to_string().bold());
    info!("Batch {} completed: {} objects processed and written to disk", batch_number, total_objects.to_string().bold());
    info!("------------------------------------");
    
    Ok(())
}

/// Process and write relationship data after all batches have been processed
pub fn process_relationships(
    common_args: &Options,
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
    fqdn_sid: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    info!("Processing cross-batch relationships...");
    
    // Create the filename
    let datetime = return_current_fulldate();
    let domain_format = common_args.domain.replace(".", "_");
    
    // For zip output
    let mut json_result: HashMap<String, String> = HashMap::new();
    
    // Create a relationships file
    let relationship_data = format!(
        "{{\"dn_sid\": {}, \"sid_type\": {}, \"fqdn_sid\": {}}}",
        serde_json::to_string(dn_sid)?,
        serde_json::to_string(sid_type)?,
        serde_json::to_string(fqdn_sid)?
    );
    
    // Write the relationships to a file
    let relationships_filename = format!("{}_{}_relationships.json", datetime, domain_format);
    let relationships_filepath = format!("{}/{}", common_args.path, relationships_filename);
    
    // Write to file - borrow the string instead of moving it
    std::fs::write(&relationships_filepath, &relationship_data)?;
    info!("Cross-batch relationships written to {}", relationships_filepath);
    
    // Add to zip if requested
    if common_args.zip {
        json_result.insert("relationships".to_string(), relationship_data);
        common::make_a_zip(
            &datetime,
            &format!("{}_relationships", domain_format),
            &common_args.path,
            &json_result,
        );
    }
    
    info!("Relationship processing complete! This data can be used with BloodHound to connect objects across batch files.");
    Ok(())
} 