pub mod modules;
pub mod enums;
pub mod json;

pub mod args;
pub mod objects;
pub mod utils;
pub mod banner;
pub mod ldap;

use log::{info, trace, error, debug};
use env_logger::Builder;
use std::collections::HashMap;
use std::error::Error;

#[cfg(not(feature = "noargs"))]
use args::{Options, extract_args};
#[cfg(feature = "noargs")]
use args::auto_args;

use banner::{print_banner, print_end_banner};
use ldap::ldap_search;
use modules::run_modules;
use json::{
    parser::parse_result_type,
    checker::check_all_result,
    maker::make_result,
};
use objects::{
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

/// Main of RustHound
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Banner
    print_banner();

    // Get args
    #[cfg(not(feature = "noargs"))]
    let common_args: Options = extract_args();
    #[cfg(feature = "noargs")]
    let common_args = auto_args();

    // Build logger
    Builder::new()
        .filter(Some("rusthound"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    // Get verbose level
    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);
    
    // Log batching configuration
    if let Some(batch_size) = common_args.batch_size {
        info!("Batch processing enabled with size: {}", batch_size);
        info!("Data will be written to disk after every {} objects", batch_size);
    } else {
        info!("Batch processing disabled - all objects will be kept in memory until processing completes");
    }

    // LDAP request to get all informations in result
    info!("Starting LDAP search...");
    let result = ldap_search(
        common_args.ldaps,
        &common_args.ip,
        &common_args.port,
        &common_args.domain,
        &common_args.ldapfqdn,
        &common_args.username,
        &common_args.password,
        common_args.kerberos,
        &common_args.ldap_filter
    ).await?;
    info!("LDAP search completed. Retrieved {} objects to process", result.len());

    // Vector for content all
    let mut vec_users:              Vec<User>            = Vec::new();
    let mut vec_groups:             Vec<Group>           = Vec::new();
    let mut vec_computers:          Vec<Computer>        = Vec::new();
    let mut vec_ous:                Vec<Ou>              = Vec::new();
    let mut vec_domains:            Vec<Domain>          = Vec::new();
    let mut vec_gpos:               Vec<Gpo>             = Vec::new();
    let mut vec_fsps:               Vec<Fsp>             = Vec::new();
    let mut vec_containers:         Vec<Container>       = Vec::new();
    let mut vec_trusts:             Vec<Trust>           = Vec::new();
    let mut vec_ntauthstores:       Vec<NtAuthStore>     = Vec::new();
    let mut vec_aiacas:             Vec<AIACA>           = Vec::new();
    let mut vec_rootcas:            Vec<RootCA>          = Vec::new();
    let mut vec_enterprisecas:      Vec<EnterpriseCA>    = Vec::new();
    let mut vec_certtemplates:      Vec<CertTemplate>    = Vec::new();
    let mut vec_issuancepolicies:   Vec<IssuancePolicie> = Vec::new();

    debug!("Initialized empty vectors for all object types");

    // Hashmap to link DN to SID
    let mut dn_sid: HashMap<String, String> = HashMap::new();
    // Hashmap to link DN to Type
    let mut sid_type: HashMap<String, String> = HashMap::new();
    // Hashmap to link FQDN to SID
    let mut fqdn_sid: HashMap<String, String> = HashMap::new();
    // Hashmap to link fqdn to an ip address
    let mut fqdn_ip: HashMap<String, String> = HashMap::new();

    // Analyze object by object 
    // Get type and parse it to get values
    info!("Starting object parsing and processing...");
    let parse_start_time = std::time::Instant::now();
    
    parse_result_type(
        &common_args,
        result,
        &mut vec_users,
        &mut vec_groups,
        &mut vec_computers,
        &mut vec_ous,
        &mut vec_domains,
        &mut vec_gpos,
        &mut vec_fsps,
        &mut vec_containers,
        &mut vec_trusts,
        &mut vec_ntauthstores,
        &mut vec_aiacas,
        &mut vec_rootcas,
        &mut vec_enterprisecas,
        &mut vec_certtemplates,
        &mut vec_issuancepolicies,
        &mut dn_sid,
        &mut sid_type,
        &mut fqdn_sid,
        &mut fqdn_ip,
    )?;
    
    let parse_duration = parse_start_time.elapsed();
    info!("Object parsing completed in {:.2} seconds", parse_duration.as_secs_f64());
    
    // Functions to replace and add missing values
    if common_args.batch_size.is_none() {
        // Only need to do post-processing if we're not using batching
        // (otherwise vectors will be empty at this point)
        info!("Running post-processing to add missing values and relationships...");
        let post_process_start = std::time::Instant::now();
        
        check_all_result(
            &common_args,
            &mut vec_users,
            &mut vec_groups,
            &mut vec_computers,
            &mut vec_ous,
            &mut vec_domains,
            &mut vec_gpos,
            &mut vec_fsps,
            &mut vec_containers,
            &mut vec_trusts,
            &mut vec_ntauthstores,
            &mut vec_aiacas,
            &mut vec_rootcas,
            &mut vec_enterprisecas,
            &mut vec_certtemplates,
            &mut vec_issuancepolicies,
            &mut dn_sid,
            &mut sid_type,
            &mut fqdn_sid,
            &mut fqdn_ip,
        )?;
        
        let post_process_duration = post_process_start.elapsed();
        info!("Post-processing completed in {:.2} seconds", post_process_duration.as_secs_f64());
    } else {
        info!("Skipping post-processing step as batch processing was used");
        info!("All objects have already been processed and written to files");
    }

    // Running modules
    info!("Running additional modules...");
    let modules_start = std::time::Instant::now();
    
    run_modules(
        &common_args,
        &mut fqdn_ip,
        &mut vec_computers,
    ).await?;
    
    let modules_duration = modules_start.elapsed();
    info!("Module execution completed in {:.2} seconds", modules_duration.as_secs_f64());

    // Add all in json files
    // Only do final result writing if we're not using batching
    if common_args.batch_size.is_none() {
        info!("Writing all collected data to output files...");
        let write_start = std::time::Instant::now();
        
        match make_result(
            &common_args,
            vec_users,
            vec_groups,
            vec_computers,
            vec_ous,
            vec_domains,
            vec_gpos,
            vec_containers,
            vec_ntauthstores,
            vec_aiacas,
            vec_rootcas,
            vec_enterprisecas,
            vec_certtemplates,
            vec_issuancepolicies,
        ) {
            Ok(_res) => {
                let write_duration = write_start.elapsed();
                info!("Writing to files completed in {:.2} seconds", write_duration.as_secs_f64());
                trace!("Making json/zip files finished!");
            },
            Err(err) => error!("Error writing output files. Reason: {err}")
        }
    } else {
        // Calculate summary stats about all batches
        info!("Batched processing summary:");
        if let Some(batch_size) = common_args.batch_size {
            info!("All data has been processed in batches of {} objects", batch_size);
            info!("All batches have been written to files with the batch number suffix");
            info!("No additional file writing needed");
        }
    }

    // End banner
    print_end_banner();
    Ok(())
}
