//! Núcleo de filtrado de NoMore.
//!
//! Decide qué hacer con cada consulta DNS: responder con un bloqueo, redirigir
//! un buscador a su modo seguro o reenviarla. No abre sockets ni lee ficheros:
//! las listas llegan ya en memoria y las consultas las reenvía quien la usa.
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
mod dns;
mod domain;
mod error;
mod policy;
mod safesearch;

pub use blocklist::{Category, CategoryList};
pub use dns::{Action, RewriteToken};
pub use domain::DomainName;
pub use error::FilterError;
pub use policy::{Filter, Policy, Verdict};
