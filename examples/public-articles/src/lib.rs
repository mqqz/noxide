#[noxide::app]
mod articles {
    use noxide::prelude::*;
    #[asset("site.css", Css)]
    pub struct Site;
    #[asset("tile.png", Png)]
    pub struct Tile;
    #[asset("proof.woff2", Woff2)]
    pub struct ProofFont;

    fn demo_page() -> Page {
        let rich=navigation("Local assets",ClassTokens::new(vec!["card".into()]).unwrap(),vec![
            image::<Tile>("An original blue and gold tile"),
            element(Element::Paragraph,ClassTokens::default(),vec![PresentationNode::Text("A local font, safe text: <script src='https://attacker.invalid/x'></script>".into())]),
            element(Element::Details,ClassTokens::default(),vec![element(Element::Summary,ClassTokens::default(),vec![PresentationNode::Text("More information".into())]),element(Element::Paragraph,ClassTokens::default(),vec![PresentationNode::Text("Native details work without scripts.".into())])]),
            element(Element::Table,ClassTokens::default(),vec![element(Element::Caption,ClassTokens::default(),vec![PresentationNode::Text("Asset types".into())]),element(Element::Row,ClassTokens::default(),vec![element(Element::HeaderCell,ClassTokens::default(),vec![PresentationNode::Text("Type".into())]),element(Element::Cell,ClassTokens::default(),vec![PresentationNode::Text("PNG / WOFF2 / CSS".into())])])]),
            route_link(routes::index(),"Published articles"),
        ]);
        Page::new(
            "Local asset demo",
            html! { (stylesheet::<Site>()) main { h1 { "Local asset demo" } (rich) } },
        )
    }
    #[page(path="/assets_demo",access=public)]
    fn asset_demo() -> Page {
        demo_page()
    }
    #[page(path = "/assets_preview")]
    fn asset_preview() -> Page {
        demo_page()
    }

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
    #[cfg(test)]
    mod asset_tests {
        use super::*;
        #[test]
        fn app_assets_match_explicit_registration_and_typed_ir() {
            let actual: noxide::__private::Manifest =
                serde_json::from_str(&noxide_manifest()).unwrap();
            let mut explicit = noxide::ApplicationDefinition::new();
            for asset in [
                Site::declaration(),
                Tile::declaration(),
                ProofFont::declaration(),
            ] {
                explicit.asset(asset);
            }
            asset_demo::register(&mut explicit);
            asset_preview::register(&mut explicit);
            category::register(&mut explicit);
            overview::register(&mut explicit);
            highlights::register(&mut explicit);
            index::register(&mut explicit);
            show::register(&mut explicit);
            assert_eq!(actual, explicit.manifest());
            assert_eq!(actual.assets.len(), 3);
            let mut typed = Fragment::new();
            typed.append(stylesheet::<Site>());
            typed.append(image::<Tile>("tile"));
            let response = noxide::IntoPageResponse::into_response(Page::new("Typed", typed));
            assert_eq!(
                response,
                noxide::ResponseIntent::Page(noxide::Document::new(
                    "Typed",
                    vec![
                        noxide::Instruction::Stylesheet {
                            asset: "site.css".into()
                        },
                        noxide::Instruction::Rich(PresentationNode::Image {
                            asset: "tile.png".into(),
                            alt: "tile".into(),
                            classes: ClassTokens::default()
                        })
                    ]
                ))
            );
        }
    }
}
