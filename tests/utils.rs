use scant3r::utils::*;

#[test]
fn random_str_length_and_case() {
    let s = random_str(5);
    assert_eq!(s.len(), 5);
    assert!(s.chars().all(|c| c.is_ascii_uppercase()));
}

#[test]
fn test_remove_dups() {
    assert_eq!(
        remove_dups(&["item".into(), "item2".into(), "item".into()]),
        vec!["item".to_string(), "item2".to_string()]
    );
}

#[test]
fn test_remove_dups_urls() {
    let urls = vec![
        "http://google.com/?test=1".to_string(),
        "http://php.net/?test=1".to_string(),
        "http://google.com/?test=1".to_string(),
        "not-a-url".to_string(),
    ];
    assert_eq!(
        remove_dups_urls(&urls),
        vec![
            "http://google.com/?test=1".to_string(),
            "http://php.net/?test=1".to_string()
        ]
    );
}

#[test]
fn test_insert_to_params_name() {
    assert_eq!(
        insert_to_params_name("http://google.com/?name=1", "PAYLOAD"),
        "http://google.com/?namePAYLOAD=1"
    );
}

#[test]
fn test_insert_to_custom_params() {
    // the Python version appends to *every* parameter value
    assert_eq!(
        insert_to_custom_params("http://google.com/?test=TEST&name=5", "test", "YES", false),
        "http://google.com/?test=TESTYES&name=5YES"
    );
    assert_eq!(
        insert_to_custom_params("http://google.com/?test=1&name=5", "test", "YES", true),
        "http://google.com/?test=YES&name=YES"
    );
    // missing parameter -> url unchanged
    assert_eq!(
        insert_to_custom_params("http://google.com/?a=1", "nope", "YES", false),
        "http://google.com/?a=1"
    );
}

#[test]
fn test_insert_to_params_urls() {
    assert_eq!(
        insert_to_params_urls("http://php.net/?name=2", "test", false),
        vec!["http://php.net/?name=2test".to_string()]
    );
    assert_eq!(
        insert_to_params_urls("http://php.net/?name=2", "test", true),
        vec!["http://php.net/?name=test".to_string()]
    );
    // cumulative mutation quirk of the Python version
    assert_eq!(
        insert_to_params_urls("http://php.net/?a=1&b=2", "X", false),
        vec![
            "http://php.net/?a=1X&b=2".to_string(),
            "http://php.net/?a=1X&b=2X".to_string()
        ]
    );
}

#[test]
fn test_insert_text_to_urlpath() {
    assert_eq!(
        insert_text_to_urlpath("http://php.net/search/text/", "TEST"),
        vec![
            "http://php.net/searchTEST/text/".to_string(),
            "http://php.net/search/textTEST/".to_string()
        ]
    );
}

#[test]
fn test_post_data() {
    assert_eq!(
        post_data("http://google.com/?test=1&name=khaled"),
        vec![("test".to_string(), "1".to_string()), ("name".to_string(), "khaled".to_string())]
    );
    assert_eq!(
        post_data("?test=1&name=khaled"),
        vec![("test".to_string(), "1".to_string()), ("name".to_string(), "khaled".to_string())]
    );
}

#[test]
fn test_dump_params() {
    assert_eq!(dump_params("http://google.com/?test=1&name=5"), "test=1&name=5");
}

#[test]
fn test_add_path() {
    assert_eq!(add_path("http://google.com/", "/admin/index.php"), "http://google.com/admin/index.php");
}

#[test]
fn test_extract_headers() {
    let h = extract_headers("User-agent: YES\nHacker: 3");
    assert_eq!(h["User-agent"], "YES");
    assert_eq!(h["Hacker"], "3");
}

#[test]
fn test_extract_cookie() {
    let c = extract_cookie("session=test");
    assert_eq!(c["session"], "test");
    let c = extract_cookie("cookie1=1; cookie2=2");
    assert_eq!(c["cookie1"], "1");
    assert_eq!(c["cookie2"], "2");
    assert!(extract_cookie("").is_empty());
}

#[test]
fn test_insert_after() {
    // actual behavior of the Python code (its docstring said "Hello Morld",
    // but the code inserts *after* the match, keeping the "W")
    assert_eq!(insert_after("Hello World", "W", "M"), "Hello WMorld");
}

#[test]
fn test_urlencoder() {
    assert_eq!(urlencoder("<", 1), "%3c");
    assert_eq!(urlencoder("<", 2), "%25%33%63");
    assert_eq!(urlencoder("<", 3), "%25%32%35%25%33%33%25%36%33");
}
