mod board {
    use noxide::prelude::*;

    // item
    #[derive(Resource)]
    #[resource(key = "settings")]
    pub struct Setting {
        #[id]
        id: Id<Self>,
        #[field(key = "label", label = "Label", max_bytes = 128)]
        label: String,
    }

    // item
    #[derive(Resource)]
    #[resource(key = "team_notes")]
    pub struct TeamNote {
        #[id]
        id: Id<Self>,
        #[field(key = "body", label = "Body", max_bytes = 256)]
        body: String,
        #[field(key = "private_hint", label = "Private hint", max_bytes = 256)]
        private_hint: String,
    }

    // item
    #[derive(Resource)]
    #[resource(key = "guest_posts")]
    pub struct GuestPost {
        #[id]
        id: Id<Self>,
        #[field(key = "body", label = "Body", max_bytes = 256)]
        body: String,
        #[field(key = "published", label = "Published")]
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
    #[page(path = "/")]
    fn index(mut settings: Query<__Noxide_list_Setting>, create: Form<CreateSetting>) -> Page {
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
    #[page(path = "/settings/{setting}")]
    fn show_setting(setting: Id<Setting>, mut read: Query<__Noxide_read_Setting>, edit: Form<EditSetting>, delete: Form<DeleteSetting>) -> PageResult {
        let setting = read.get(setting).ok_or(NotFound)?;
        Ok(Page::new("Setting", html! { main { p { (&setting.label) } (edit) (delete) } }))
    }

    // item
    #[page(path = "/team")]
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
    #[page(path = "/team/{note}")]
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
    #[page(path = "/my_posts")]
    fn mine(mut posts: Query<__Noxide_list_GuestPost>) -> Page {
        Page::new("My posts", html! { main { @for post in posts.fetch() { p { (&post.body) } } } })
    }


    #[query(list(Setting), allow = owner)]
    struct __Noxide_list_Setting;
    #[query(read(Setting), allow = owner)]
    struct __Noxide_read_Setting;
    #[query(list(GuestPost), allow = owner)]
    struct __Noxide_list_GuestPost;

    #[action(create(Setting), fields(label), allow = owner, redirect = show_setting)]
    struct CreateSetting;
    #[action(update(Setting), fields(label), allow = owner, redirect = show_setting)]
    struct EditSetting;
    #[action(delete(Setting), allow = owner, redirect = index)]
    struct DeleteSetting;

    #[action(create(TeamNote), fields(body, private_hint), allow = all(same_tenant, role("writer")), redirect = show_team_note)]
    struct CreateTeamNote;
    #[action(update(TeamNote), fields(body), allow = all(same_tenant, any(owner, tenant_role("editor"))), redirect = show_team_note)]
    struct EditTeamNote;
    #[action(delete(TeamNote), allow = all(same_tenant, tenant_role("admin")), redirect = team)]
    struct DeleteTeamNote;

    #[action(create(GuestPost), fields(body, published), allow = public, redirect = show_post)]
    struct CreatePost;
    #[action(update(GuestPost), fields(body), allow = capability, redirect = show_post)]
    struct EditPost;
    #[action(delete(GuestPost), allow = capability, redirect = posts)]
    struct DeletePost;

    noxide::application! {
        pages: [index, show_setting, team, show_team_note, posts, show_post, mine],
        actions: [CreateSetting, EditSetting, DeleteSetting, CreateTeamNote, EditTeamNote, DeleteTeamNote, CreatePost, EditPost, DeletePost],
        forms: [],
    }
}
pub use board::noxide_manifest;
