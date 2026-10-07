fn main() {
    let user_input = String::from("SELECT 1; DROP TABLE vault");
    let _ = bv_sql_guard::sql!(user_input);
}
