use clap::Parser;
use derive_more::Deref;

use crate::{
    cli::command::{self, CommandExecutor},
    errors::RvError,
};

#[derive(Parser, Deref)]
#[command(author, version, about = r#"Lists the names of the policies that are installed on the BastionVault server."#)]
pub struct List {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for List {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.list_policy() {
            Ok(ret) => {
                if ret.response_status == 200 {
                    let value = ret.response_data.as_ref().unwrap();
                    let keys = &value["keys"];
                    if *keys == serde_json::from_str::<serde_json::Value>("[]").unwrap() {
                        ret.print_debug_info();
                        println!("No policy");
                        return Err(RvError::ErrRequestNoData);
                    }
                    self.output.print_value(keys, false)?;
                } else if ret.response_status == 404 {
                    ret.print_debug_info();
                    println!("No policy");
                    return Err(RvError::ErrRequestNoData);
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{e}"),
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_utils::TestHttpServer;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_cli_policy_list() {
        let mut test_http_server = TestHttpServer::new("test_cli_policy_list", true).await;
        test_http_server.token = test_http_server.root_token.clone();

        // list policy — the seeded ownership-aware baselines and the
        // legacy `standard-user` all ship by default.
        let ret = test_http_server.cli(&["policy", "list"], &[]);
        assert!(ret.is_ok());
        #[cfg(windows)]
        assert_eq!(
            ret.unwrap(),
            "default    \r\npki-admin    \r\npki-user    \r\nsecret-author    \r\nstandard-user    \r\nstandard-user-readonly    \r\ntotp-admin    \r\ntotp-user    \r\nroot    \r\n",
        );
        #[cfg(not(windows))]
        assert_eq!(
            ret.unwrap(),
            "default    \npki-admin    \npki-user    \nsecret-author    \nstandard-user    \nstandard-user-readonly    \ntotp-admin    \ntotp-user    \nroot    \n",
        );

        // write a test policy
        let test_policy = r#"path "secret/" {}"#;
        let client = test_http_server.client().unwrap();
        let sys = client.sys();
        assert!(sys.write_policy("my-policy", test_policy).is_ok());

        // list policy again
        let ret = test_http_server.cli(&["policy", "list"], &[]);
        assert!(ret.is_ok());
        #[cfg(windows)]
        assert_eq!(
            ret.unwrap(),
            "default    \r\nmy-policy    \r\npki-admin    \r\npki-user    \r\nsecret-author    \r\nstandard-user    \r\nstandard-user-readonly    \r\ntotp-admin    \r\ntotp-user    \r\nroot    \r\n",
        );
        #[cfg(not(windows))]
        assert_eq!(
            ret.unwrap(),
            "default    \nmy-policy    \npki-admin    \npki-user    \nsecret-author    \nstandard-user    \nstandard-user-readonly    \ntotp-admin    \ntotp-user    \nroot    \n",
        );

        // list policy with table format
        let ret = test_http_server.cli(&["policy", "list"], &["--format=table"]);
        assert!(ret.is_ok());
        #[cfg(windows)]
        assert_eq!(
            ret.unwrap(),
            "default    \r\nmy-policy    \r\npki-admin    \r\npki-user    \r\nsecret-author    \r\nstandard-user    \r\nstandard-user-readonly    \r\ntotp-admin    \r\ntotp-user    \r\nroot    \r\n",
        );
        #[cfg(not(windows))]
        assert_eq!(
            ret.unwrap(),
            "default    \nmy-policy    \npki-admin    \npki-user    \nsecret-author    \nstandard-user    \nstandard-user-readonly    \ntotp-admin    \ntotp-user    \nroot    \n",
        );

        // list policy with json format
        let ret = test_http_server.cli(&["policy", "list"], &["--format=json"]);
        assert!(ret.is_ok());
        assert_eq!(
            ret.unwrap(),
            "[\n  \"default\",\n  \"my-policy\",\n  \"pki-admin\",\n  \"pki-user\",\n  \"secret-author\",\n  \"standard-user\",\n  \"standard-user-readonly\",\n  \"totp-admin\",\n  \"totp-user\",\n  \"root\"\n]\n",
        );

        // list policy with yaml format
        let ret = test_http_server.cli(&["policy", "list"], &["--format=yaml"]);
        assert!(ret.is_ok());
        assert_eq!(
            ret.unwrap(),
            "- default\n- my-policy\n- pki-admin\n- pki-user\n- secret-author\n- standard-user\n- standard-user-readonly\n- totp-admin\n- totp-user\n- root\n",
        );
    }
}
