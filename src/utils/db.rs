use std::path::Path;
use url::Url;

use crate::errors::RvError;

#[derive(Debug)]
pub enum DatabaseName {
    MySql(String),
    Sqlite(String),
}

impl DatabaseName {
    pub fn from_url(database_url: &str) -> Result<Self, RvError> {
        let parsed = Url::parse(database_url)?;
        let scheme = parsed.scheme();

        match scheme {
            "mysql" => {
                let path = parsed.path().strip_prefix('/').unwrap_or(parsed.path());
                if path.is_empty() {
                    return Err(RvError::ErrString("Database name is empty".to_string()));
                }
                Ok(DatabaseName::MySql(path.to_string()))
            }
            "sqlite" | "sqlite3" => {
                let path = parsed.path();
                let file_name = Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or(RvError::ErrString("Invalid SQLite file path".to_string()))?;
                Ok(DatabaseName::Sqlite(file_name.to_string()))
            }
            scheme => Err(RvError::ErrString(format!("Unsupported database scheme: {scheme}"))),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            DatabaseName::MySql(name) | DatabaseName::Sqlite(name) => name,
        }
    }

    pub fn scheme(&self) -> &str {
        match self {
            DatabaseName::MySql(_) => "mysql",
            DatabaseName::Sqlite(_) => "sqlite",
        }
    }
}

pub fn strip_db_name(url: &str) -> String {
    if let Some(idx) = url.rfind('/') {
        url[..=idx].to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mysql_url_parsing() {
        let url = "mysql://user:password@localhost:3306/mydb";
        let db_name = DatabaseName::from_url(url).unwrap();
        assert!(matches!(db_name, DatabaseName::MySql(_)));
        assert_eq!(db_name.name(), "mydb");
    }

    #[test]
    fn test_sqlite_url_parsing() {
        let url = "sqlite:///path/to/database.db";
        let db_name = DatabaseName::from_url(url).unwrap();
        assert!(matches!(db_name, DatabaseName::Sqlite(_)));
        assert_eq!(db_name.name(), "database.db");
    }

    #[test]
    fn test_sqlite3_url_parsing() {
        let url = "sqlite3:///path/to/database.db";
        let db_name = DatabaseName::from_url(url).unwrap();
        assert!(matches!(db_name, DatabaseName::Sqlite(_)));
        assert_eq!(db_name.name(), "database.db");
    }

    #[test]
    fn test_sqlite_with_complex_path() {
        let url = "sqlite:///home/user/data/apps/myapp/database.sqlite3";
        let db_name = DatabaseName::from_url(url).unwrap();
        assert!(matches!(db_name, DatabaseName::Sqlite(_)));
        assert_eq!(db_name.name(), "database.sqlite3");
    }

    #[test]
    fn test_mysql_with_fragment() {
        let url = "mysql://user:password@localhost:3306/mydb#section";
        let db_name = DatabaseName::from_url(url).unwrap();
        assert!(matches!(db_name, DatabaseName::MySql(_)));
        assert_eq!(db_name.name(), "mydb");
    }

    #[test]
    fn test_empty_database_name_mysql() {
        let url = "mysql://user:password@localhost:3306/";
        let result = DatabaseName::from_url(url);
        assert!(result.is_err());
        if let Err(RvError::ErrString(msg)) = result {
            assert_eq!(msg, "Database name is empty");
        } else {
            panic!("Expected ErrString error");
        }
    }

    #[test]
    fn test_postgres_scheme_unsupported() {
        let url = "postgres://user:password@localhost:5432/mydb";
        let result = DatabaseName::from_url(url);
        assert!(result.is_err());
        if let Err(RvError::ErrString(msg)) = result {
            assert!(msg.contains("Unsupported database scheme: postgres"));
        } else {
            panic!("Expected ErrString error");
        }
    }

    #[test]
    fn test_unsupported_scheme() {
        let url = "oracle://user:password@localhost:1521/mydb";
        let result = DatabaseName::from_url(url);
        assert!(result.is_err());
        if let Err(RvError::ErrString(msg)) = result {
            assert!(msg.contains("Unsupported database scheme: oracle"));
        } else {
            panic!("Expected ErrString error");
        }
    }

    #[test]
    fn test_invalid_url() {
        let url = "not-a-valid-url";
        let result = DatabaseName::from_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_sqlite_invalid_path() {
        let url = "sqlite:///";
        let result = DatabaseName::from_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_database_name_method() {
        let mysql_db = DatabaseName::MySql("testdb".to_string());
        assert_eq!(mysql_db.name(), "testdb");

        let sqlite_db = DatabaseName::Sqlite("test.db".to_string());
        assert_eq!(sqlite_db.name(), "test.db");
    }

    #[test]
    fn test_mysql_with_ip_address() {
        let url = "mysql://user:password@192.168.1.100:3306/localdb";
        let db_name = DatabaseName::from_url(url).unwrap();
        assert_eq!(db_name.name(), "localdb");
    }
}
