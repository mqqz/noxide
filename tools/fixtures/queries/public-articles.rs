#[noxide::app]
mod articles {
    use noxide::prelude::*;

    #[derive(Choice)]
    pub enum Category {
        #[choice(key = "books", label = "Books")]
        Books,
        #[choice(key = "games", label = "Games")]
        Games,
    }

    // Owner shorthand can coexist with explicitly approved public projections.
    #[derive(Resource)]
    #[resource(key = "articles", owner)]
    pub struct Article {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 256)]
        title: String,
        #[field(max_bytes = 4096)]
        body: String,
        #[field()]
        published: bool,
        #[field(max_bytes = 1024)]
        private_notes: String,
        #[field()]
        category: Category,
    }

    #[query(list(Article), allow = public, visible(published = true), fields(title, body))]
    struct PublishedArticles;

    #[query(list(Article), allow = public, visible(published = true),
        filter(category = param(category)), disclose(category), fields(title, body), page_size = 1)]
    struct CategoryArticles;

    #[page(path = "/categories", access = public, params(category))]
    fn category(mut articles: Query<CategoryArticles>) -> Page {
        let category = articles
            .param("category")
            .expect("bound category")
            .to_owned();
        Page::new(
            "Category",
            html! { main {
                h1 { (&category) }
                @for article in articles.fetch() { p { (&article.title) } }
                a href=(routes::category(Category::Books)) { "Books" }
                a href=(routes::category(Category::Games)) { "Games" }
            } },
        )
    }

    #[query(list(Article), allow = public, visible(published = true),
        filter(category = param(category)), disclose(category), fields(title, body),
        page_size = 1, preview(see_all = category))]
    struct CategoryPreview;

    #[page(path = "/overview", params(category), access = public)]
    fn overview(mut articles: Query<CategoryArticles>, mut sample: Query<CategoryPreview>) -> Page {
        let articles = articles.fetch();
        let sample = sample.fetch_preview();
        Page::new(
            "Overview",
            html! { main {
                h1 { "Category overview" }
                @for article in &articles { p { (&article.title) } }
                h2 { "Preview" }
                @for article in &sample.items { p { (&article.title) } }
                @if sample.truncated { p { "More in category" } }
            } },
        )
    }

    #[page(path = "/highlights", params(category), access = public)]
    fn highlights(mut sample: Query<CategoryPreview>) -> Page {
        let sample = sample.fetch_preview();
        Page::new(
            "Highlights",
            html! { main {
                h1 { "Highlights" }
                @for article in &sample.items { p { (&article.title) } }
                @if sample.truncated { p { "More in category" } }
            } },
        )
    }

    #[query(read(Article), allow = public, visible(published = true), fields(title, body))]
    struct PublishedArticle;

    #[page(path = "/", access = public)]
    fn index(mut articles: Query<PublishedArticles>) -> Page {
        Page::new(
            "Articles",
            html! {
                main {
                    h1 { "Articles" }
                    @for article in articles.fetch() {
                        article {
                            h2 { (&article.title) }
                            a href=(routes::show(article.id())) { "Read article" }
                        }
                    }
                }
            },
        )
    }

    #[page(path = "/articles/{article}", access = public)]
    fn show(article: Id<Article>, mut read: Query<PublishedArticle>) -> PageResult {
        let article = read.get(article).ok_or(NotFound)?;
        Ok(Page::new(
            &article.title,
            html! {
                main {
                    h1 { (&article.title) }
                    p { (&article.body) }
                    a href=(routes::index()) { "All articles" }
                }
            },
        ))
    }
}
