//! Núcleo de filtrado de NoMore.
//!
//! Decide qué hacer con un dominio: bloquearlo, permitirlo o tratarlo como
//! canario. No abre sockets ni lee ficheros; las listas llegan ya en memoria.
//!
//! ```
//! use filter_core::{Category, CategoryList, Filter, Policy, Verdict};
//!
//! let porn = CategoryList::build(Category::Porn, ["pornhub.com"]).unwrap();
//! let filter = Filter::new(
//!     vec![CategoryList::parse(&porn).unwrap()],
//!     Policy::default(),
//! )
//! .unwrap();
//!
//! assert_eq!(filter.explain("es.pornhub.com"), Verdict::Blocked(Category::Porn));
//! assert_eq!(filter.explain("wikipedia.org"), Verdict::Allowed);
//! ```

mod blocklist;
mod domain;
mod error;
mod policy;

pub use blocklist::{Category, CategoryList};
pub use domain::DomainName;
pub use error::FilterError;
pub use policy::{Filter, Policy, Verdict};
