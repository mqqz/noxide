mod articles {
    use noxide::prelude::*;

    // Owner shorthand can coexist with explicitly approved public projections.
    #[derive(Resource)]
    #[resource(key = "articles")]
    pub struct Article {
        #[id]
        id: Id<Self>,
        #[field(key = "title", label = "Title", max_bytes = 256)]
        title: String,
        #[field(key = "body", label = "Body", max_bytes = 4096)]
        body: String,
        #[field(key = "published", label = "Published")]
        published: bool,
        #[field(key = "private_notes", label = "Private notes", max_bytes = 1024)]
        private_notes: String,
    }

    #[query(list(Article), allow = public, visible(published = true), fields(title, body))]
    struct PublishedArticles;

    #[query(read(Article), allow = public, visible(published = true), fields(title, body))]
    struct PublishedArticle;

    #[page(path = "/", access = public)]
    fn index(mut articles: Query<PublishedArticles>) -> Page {
        Page::new("Articles", html! {
            main {
                h1 { "Articles" }
                @for article in articles.fetch() {
                    article {
                        h2 { (&article.title) }
                        a href=(routes::show(article.id())) { "Read article" }
                    }
                }
            }
        })
    }

    #[page(path = "/articles/{article}", access = public)]
    fn show(article: Id<Article>, mut read: Query<PublishedArticle>) -> PageResult {
        let article = read.get(article).ok_or(NotFound)?;
        Ok(Page::new(&article.title, html! {
            main {
                h1 { (&article.title) }
                p { (&article.body) }
                a href=(routes::index()) { "All articles" }
            }
        }))
    }
    noxide::application! {
        pages: [index, show], actions: [], forms: [],
    }
}
pub use articles::noxide_manifest;
