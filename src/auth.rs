//! Helpers to manage GCP authentication.
use crate::error::BQError;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use std::sync::Arc;
use yup_oauth2::authenticator::Authenticator;
use yup_oauth2::ServiceAccountKey;
use std::env;

/// A service account authenticator.
#[derive(Clone)]
pub struct ServiceAccountAuthenticator {
    auth: Option<Arc<Authenticator<HttpsConnector<HttpConnector>>>>,
    scopes: Vec<String>,
    is_using_workload_identity: bool,
}

impl ServiceAccountAuthenticator {
    /// Returns an access token.
    pub async fn access_token(&self) -> Result<String, BQError> {
        let token = if self.is_using_workload_identity {
            get_access_token_with_workload_identity().await?.access_token
        } else {
            self.auth
                .clone()
                .unwrap()
                .token(self.scopes.as_ref())
                .await?
                .as_str()
                .to_string()
        };
        Ok(token)
    }

    pub(crate) async fn from_service_account_key(
        sa_key: ServiceAccountKey,
        scopes: &[&str],
    ) -> Result<ServiceAccountAuthenticator, BQError> {
        let auth = yup_oauth2::ServiceAccountAuthenticator::builder(sa_key).build().await;

        match auth {
            Err(err) => Err(BQError::InvalidServiceAccountAuthenticator(err)),
            Ok(auth) => Ok(ServiceAccountAuthenticator {
                auth: Some(Arc::new(auth)),
                scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
                is_using_workload_identity: false,
            }),
        }
    }

    pub(crate) async fn from_authorized_user(
        path: &str,
        scopes: &[&str],
    ) -> Result<ServiceAccountAuthenticator, BQError> {
        let secret = yup_oauth2::read_authorized_user_secret(path).await?;
    
        let auth_flow = yup_oauth2::AuthorizedUserAuthenticator::builder(secret);
        let auth = auth_flow.build().await?;
    
        Ok(ServiceAccountAuthenticator {
            auth: Some(Arc::new(auth)),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            is_using_workload_identity: false,
        })
    }

    pub(crate) async fn with_workload_identity(scopes: &[&str]) -> Result<ServiceAccountAuthenticator, BQError> {
        Ok(ServiceAccountAuthenticator {
            auth: None,
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            is_using_workload_identity: true,
        })
    }

    pub(crate) async fn auto_authenticate(scopes: &[&str]) -> Result<ServiceAccountAuthenticator, BQError> {
        //  implements ADC strategy

        if let Ok(key_file) = env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            if let Ok(_secret) = yup_oauth2::read_authorized_user_secret(&key_file).await {
                return ServiceAccountAuthenticator::from_authorized_user(&key_file, scopes).await;
            }
            if let Ok(secret) = yup_oauth2::read_service_account_key(&key_file).await {
                return ServiceAccountAuthenticator::from_service_account_key(secret, scopes).await;
            }

            dbg!("Unsupported key format under GOOGLE_APPLICATION_CREDENTIALS! Moving on.");
        }


        if let Ok(_token) = get_access_token_with_workload_identity().await {
            return ServiceAccountAuthenticator::with_workload_identity(scopes).await;
        }

        //  well known key locations
        #[cfg(target_os = "linux")]
        let config_location = "~/.config/gcloud/application_default_credentials.json";
        #[cfg(target_os = "windows")]
        let config_location = "%appdata%/gcloud/application_default_credentials.json";

        if let Ok(_secret) = yup_oauth2::read_authorized_user_secret(config_location).await {
            return ServiceAccountAuthenticator::from_authorized_user(config_location, scopes).await;
        }
        if let Ok(secret) = yup_oauth2::read_service_account_key(config_location).await {
            return ServiceAccountAuthenticator::from_service_account_key(secret, scopes).await;
        }

        Err(BQError::AuthError("Authentication failed. Auto auth exhausted all options.".to_owned()))
    }
}

pub(crate) async fn service_account_authenticator(
    scopes: Vec<&str>,
    sa_key_file: &str,
) -> Result<ServiceAccountAuthenticator, BQError> {
    let sa_key = yup_oauth2::read_service_account_key(sa_key_file).await?;
    ServiceAccountAuthenticator::from_service_account_key(sa_key, &scopes).await
}

#[derive(Deserialize)]
pub struct WorkloadIdentityAccessToken {
    pub access_token: String,
    pub expires_in: i32,
    pub token_type: String,
}

pub(crate) async fn get_access_token_with_workload_identity() -> Result<WorkloadIdentityAccessToken, BQError> {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://metadata/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?;

    let content: WorkloadIdentityAccessToken = resp.json().await?;

    Ok(content)
}
