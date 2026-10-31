# Team documents

A private workspace contains documents and account memberships. This example uses
host-enforced record membership policies; global and tenant roles are unchanged.
All pages and management forms work without JavaScript or external assets.

Build trusted source with:

```sh
noxide build --app examples/team-documents --name team_documents --framework . --output NEW_DIRECTORY
```

Review the generated contract, approve it, install its declared indexes with
`noxide schema indexes CONFIG.json`, and serve its bundle. Provision two
active accounts in the same nonempty tenant with the operator's `noxide account`
command. `noxide account-lookup CONFIG.json LOGIN` returns the account ID needed
by the member form. Account IDs identify recipients; knowing one grants no access.

1. Sign in and create a workspace. One approved transaction creates the workspace
   and its administrator membership. The membership refers to the earlier create,
   binds its account to the authenticated principal, and assigns the literal
   administrator role. Both writes and the replay receipt commit together.
2. Open the workspace and add the second account ID. The administrator policy
   authorizes management; the host checks the selected account is active and in
   the same tenant. An optional native unique constraint prevents a second
   `(workspace, account)` membership, including after revocation.
3. Sign in as the member and create or read a document. Member authority comes
   from an active, unexpired membership. Members cannot grant themselves an
   administrator role. Membership-row ownership grants no management shortcut.
4. As an administrator, edit a membership to change its role or revoke it. New
   requests immediately recheck authority. Demoting or revoking the last
   administrator removes management access; there is no implicit owner recovery.

Every workspace, membership and document expires after one hour in this example.
The approved declaration caps new expiry values at one day. Expiry hides a row
from ordinary reads and mutations; it does not delete data or release the unique
membership tuple. An expired row cannot be revived through its ordinary edit
form. Expiry checks use the host's fixed durable attempt time; unavailable or
stale lifecycle freshness makes temporal requests unavailable.

The workspace owner retains the explicitly declared workspace read grant. Document
reads and roster management have their own membership policies. These grants are
visible in the generated manifest, as are the lookup fields and expiry bounds.
Membership lookup metadata does not create a membership read or list grant.
