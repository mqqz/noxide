#[noxide::app]
mod board {
    use noxide::prelude::*;

    // item
    #[derive(Resource)]
    #[resource(key = "settings", owner)]
    pub struct Setting {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 128)]
        label: String,
    }

    // item
    #[derive(Resource)]
    #[resource(key = "team_notes")]
    pub struct TeamNote {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 256)]
        body: String,
        #[field(max_bytes = 256)]
        private_hint: String,
    }

    // item
    #[derive(Resource)]
    #[resource(key = "guest_posts", owner)]
    pub struct GuestPost {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 256)]
        body: String,
        #[field()]
        published: bool,
    }

    // item
    #[query(list(TeamNote), allow = same_tenant)]
    struct TeamNotes;

    // item
    #[query(read(TeamNote), allow = same_tenant)]
    struct ReadTeamNote;

    // item
    #[query(list(GuestPost), allow = public, visible(published = true), fields(body))]
    struct PublishedPosts;

    // item
    #[query(read(GuestPost), allow = public, visible(published = true), fields(body))]
    struct PublishedPost;

    // item
    #[page("/")]
    fn index(mut settings: List<Setting>, create: Form<CreateSetting>) -> Page {
        Page::new("Settings", html! {
            main {
                @for setting in settings.fetch() {
                    a href=(routes::show_setting(setting.id)) { (&setting.label) }
                }
                (create)
            }
        })
    }

    // item
    #[page("/settings/{setting}")]
    fn show_setting(setting: Id<Setting>, mut read: Read<Setting>, edit: Form<EditSetting>, delete: Form<DeleteSetting>) -> PageResult {
        let setting = read.get(setting).ok_or(NotFound)?;
        Ok(Page::new("Setting", html! { main { p { (&setting.label) } (edit) (delete) } }))
    }

    // item
    #[page("/team")]
    fn team(mut notes: Query<TeamNotes>, create: Form<CreateTeamNote>) -> Page {
        Page::new("Team notes", html! {
            main {
                @for note in notes.fetch() {
                    a href=(routes::show_team_note(note.id)) { (&note.body) }
                }
                (create)
            }
        })
    }

    // item
    #[page("/team/{note}")]
    fn show_team_note(note: Id<TeamNote>, mut read: Query<ReadTeamNote>, edit: Form<EditTeamNote>, delete: Form<DeleteTeamNote>) -> PageResult {
        let note = read.get(note).ok_or(NotFound)?;
        Ok(Page::new("Team note", html! { main { p { (&note.body) } p { (&note.private_hint) } (edit) (delete) } }))
    }

    // item
    #[page(path = "/posts", access = public_optional)]
    fn posts(mut posts: Query<PublishedPosts>, create: Form<CreatePost>) -> Page {
        Page::new("Posts", html! {
            main {
                @for post in posts.fetch() {
                    a href=(routes::show_post(post.id())) { (&post.body) }
                }
                (create)
            }
        })
    }

    // item
    #[page(path = "/posts/{post}", access = public_optional)]
    fn show_post(post: Id<GuestPost>, mut read: Query<PublishedPost>, edit: Form<EditPost>, delete: Form<DeletePost>) -> PageResult {
        let post = read.get(post).ok_or(NotFound)?;
        Ok(Page::new("Post", html! { main { p { (&post.body) } (edit) (delete) } }))
    }

    // item
    #[page("/my_posts")]
    fn mine(mut posts: List<GuestPost>) -> Page {
        Page::new("My posts", html! { main { @for post in posts.fetch() { p { (&post.body) } } } })
    }

    // item
    crud! { Setting {
        create CreateSetting { fields(label), redirect(show_setting) }
        update EditSetting { fields(label), redirect(show_setting) }
        delete DeleteSetting { redirect(index) }
    } }

    // item
    crud! { TeamNote {
        create CreateTeamNote { fields(body, private_hint), redirect(show_team_note), allow = all(same_tenant, role("writer")) }
        update EditTeamNote { fields(body), redirect(show_team_note), allow = all(same_tenant, any(owner, tenant_role("editor"))) }
        delete DeleteTeamNote { redirect(team), allow = all(same_tenant, tenant_role("admin")) }
    } }

    // item
    crud! { GuestPost {
        create CreatePost { fields(body, published), redirect(show_post), allow = public }
        update EditPost { fields(body), redirect(show_post), allow = capability }
        delete DeletePost { redirect(posts), allow = capability }
    } }
}
