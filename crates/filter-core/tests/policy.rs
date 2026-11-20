//! Precedencia y categorías, a través de la API pública.

use filter_core::{BlockedRule, Category, CategoryList, Filter, FilterError, Policy, Verdict};

fn list(category: Category, domains: &[&str]) -> CategoryList {
    CategoryList::parse(&CategoryList::build(category, domains).unwrap()).unwrap()
}

fn all_lists() -> Vec<CategoryList> {
    vec![
        list(Category::Porn, &["pornhub.com", "xxx"]),
        list(Category::Gambling, &["bet365.es", "loteriasyapuestas.es"]),
        list(Category::Dating, &["tinder.com", "gotinder.com"]),
        list(
            Category::Bypass,
            &["dns.google", "cloudflare-dns.com", "nordvpn.com"],
        ),
    ]
}

fn filter(policy: Policy) -> Filter {
    Filter::new(all_lists(), policy).unwrap()
}

fn allowing(domains: &[&str]) -> Policy {
    Policy {
        allowlist: domains.iter().map(|d| d.to_string()).collect(),
        ..Policy::default()
    }
}

#[test]
fn default_policy_blocks_every_category() {
    let f = filter(Policy::default());
    assert_eq!(
        f.explain("es.pornhub.com"),
        Verdict::Blocked(Category::Porn)
    );
    assert_eq!(f.explain("sitio.xxx"), Verdict::Blocked(Category::Porn));
    assert_eq!(f.explain("bet365.es"), Verdict::Blocked(Category::Gambling));
    assert_eq!(
        f.explain("api.gotinder.com"),
        Verdict::Blocked(Category::Dating)
    );
    assert_eq!(f.explain("dns.google"), Verdict::Blocked(Category::Bypass));
}

#[test]
fn unlisted_domains_are_allowed() {
    let f = filter(Policy::default());
    assert_eq!(f.explain("wikipedia.org"), Verdict::Allowed);
    assert_eq!(f.explain("notpornhub.com"), Verdict::Allowed);
    assert_eq!(f.explain("maps.google.com"), Verdict::Allowed);
}

#[test]
fn invalid_text_is_reported_as_invalid() {
    let f = filter(Policy::default());
    assert_eq!(f.explain(""), Verdict::Invalid);
    assert_eq!(f.explain("no es un dominio"), Verdict::Invalid);
}

#[test]
fn guardian_can_turn_off_gambling_and_dating() {
    let f = filter(Policy {
        block_gambling: false,
        block_dating: false,
        allowlist: vec![],
    });
    assert_eq!(f.explain("bet365.es"), Verdict::Allowed);
    assert_eq!(f.explain("tinder.com"), Verdict::Allowed);
}

#[test]
fn porn_and_bypass_stay_on_with_everything_else_off() {
    let f = filter(Policy {
        block_gambling: false,
        block_dating: false,
        allowlist: vec![],
    });
    assert_eq!(f.explain("pornhub.com"), Verdict::Blocked(Category::Porn));
    assert_eq!(f.explain("nordvpn.com"), Verdict::Blocked(Category::Bypass));
}

#[test]
fn filter_without_porn_list_is_rejected() {
    let lists = vec![list(Category::Gambling, &["bet365.es"])];
    assert_eq!(
        Filter::new(lists, Policy::default()).unwrap_err(),
        FilterError::MissingPornList
    );
}

#[test]
fn several_lists_of_one_category_are_all_used() {
    let lists = vec![
        list(Category::Porn, &["uno.com"]),
        list(Category::Porn, &["dos.com"]),
    ];
    let f = Filter::new(lists, Policy::default()).unwrap();
    assert_eq!(f.explain("uno.com"), Verdict::Blocked(Category::Porn));
    assert_eq!(f.explain("dos.com"), Verdict::Blocked(Category::Porn));
}

#[test]
fn allowlist_unblocks_a_domain_and_its_subdomains() {
    let f = filter(allowing(&["loteriasyapuestas.es"]));
    assert_eq!(
        f.explain("loteriasyapuestas.es"),
        Verdict::AllowedByGuardian
    );
    assert_eq!(
        f.explain("www.loteriasyapuestas.es"),
        Verdict::AllowedByGuardian
    );
    // El resto de la categoría sigue bloqueado.
    assert_eq!(f.explain("bet365.es"), Verdict::Blocked(Category::Gambling));
}

#[test]
fn allowlisting_a_subdomain_does_not_unblock_the_parent() {
    let f = filter(allowing(&["ayuda.tinder.com"]));
    assert_eq!(f.explain("ayuda.tinder.com"), Verdict::AllowedByGuardian);
    assert_eq!(f.explain("tinder.com"), Verdict::Blocked(Category::Dating));
}

#[test]
fn allowlist_entry_for_unlisted_domain_is_plain_allowed() {
    let f = filter(allowing(&["wikipedia.org"]));
    assert_eq!(f.explain("wikipedia.org"), Verdict::Allowed);
}

#[test]
fn allowlist_never_unblocks_bypass() {
    let f = filter(allowing(&["dns.google", "nordvpn.com"]));
    assert_eq!(f.explain("dns.google"), Verdict::Blocked(Category::Bypass));
    assert_eq!(f.explain("nordvpn.com"), Verdict::Blocked(Category::Bypass));
}

#[test]
fn bypass_wins_over_other_categories() {
    let lists = vec![
        list(Category::Porn, &["ambos.com"]),
        list(Category::Bypass, &["ambos.com"]),
    ];
    let f = Filter::new(lists, allowing(&["ambos.com"])).unwrap();
    assert_eq!(f.explain("ambos.com"), Verdict::Blocked(Category::Bypass));
}

#[test]
fn canaries_get_their_own_verdict() {
    let f = filter(Policy::default());
    assert_eq!(f.explain("use-application-dns.net"), Verdict::Canary);
    assert_eq!(f.explain("mask.icloud.com"), Verdict::Canary);
    assert_eq!(f.explain("mask-h2.icloud.com"), Verdict::Canary);
    assert_eq!(f.explain("icloud.com"), Verdict::Allowed);
}

#[test]
fn canary_wins_over_allowlist_and_lists() {
    let lists = vec![
        list(Category::Porn, &["use-application-dns.net"]),
        list(Category::Bypass, &["use-application-dns.net"]),
    ];
    let f = Filter::new(lists, allowing(&["use-application-dns.net"])).unwrap();
    assert_eq!(f.explain("use-application-dns.net"), Verdict::Canary);
}

#[test]
fn invalid_allowlist_entry_is_an_error() {
    let err = Filter::new(all_lists(), allowing(&["no válido"])).unwrap_err();
    assert_eq!(err, FilterError::InvalidDomain("no válido".into()));
}

#[test]
fn filter_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Filter>();
}

fn rule(category: Category, rule: &str) -> Option<BlockedRule> {
    Some(BlockedRule {
        category,
        rule: rule.to_owned(),
    })
}

#[test]
fn blocked_rule_names_the_list_entry_that_matched() {
    let f = filter(Policy::default());
    assert_eq!(
        f.blocked_rule("cdn.es.pornhub.com"),
        rule(Category::Porn, "pornhub.com")
    );
    assert_eq!(f.blocked_rule("sitio.xxx"), rule(Category::Porn, "xxx"));
    assert_eq!(
        f.blocked_rule("WWW.Bet365.ES."),
        rule(Category::Gambling, "bet365.es")
    );
    assert_eq!(
        f.blocked_rule("api.gotinder.com"),
        rule(Category::Dating, "gotinder.com")
    );
    assert_eq!(
        f.blocked_rule("dns.google"),
        rule(Category::Bypass, "dns.google")
    );
}

#[test]
fn blocked_rule_is_none_when_not_blocked() {
    let f = filter(allowing(&["loteriasyapuestas.es"]));
    for domain in [
        "wikipedia.org",
        "notpornhub.com",
        "www.loteriasyapuestas.es",
        "use-application-dns.net",
        "no es un dominio",
    ] {
        assert_eq!(f.blocked_rule(domain), None, "{domain}");
    }
    let off = filter(Policy {
        block_dating: false,
        ..Policy::default()
    });
    assert_eq!(off.blocked_rule("tinder.com"), None);
}

#[test]
fn blocked_rule_agrees_with_explain() {
    let f = filter(Policy::default());
    for domain in [
        "a.pornhub.com",
        "bet365.es",
        "tinder.com",
        "nordvpn.com",
        "wikipedia.org",
        "use-application-dns.net",
    ] {
        let blocked = matches!(f.explain(domain), Verdict::Blocked(_));
        assert_eq!(f.blocked_rule(domain).is_some(), blocked, "{domain}");
        if let (Verdict::Blocked(category), Some(found)) =
            (f.explain(domain), f.blocked_rule(domain))
        {
            assert_eq!(found.category, category);
        }
    }
}
