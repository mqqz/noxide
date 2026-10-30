# Private inbox

Build trusted example code with:

```sh
noxide build --app examples/private-inbox --output /tmp/private-inbox --framework .
```

Configure and approve the generated bundle following
[Running applications](../../docs/running-applications.md). Provision accounts
with the same nonempty tenant (password files should be private):

```sh
noxide account runtime.json alice alice-password team
noxide account runtime.json bob bob-password team
```

Provisioning prints each opaque ID. Sign in and visit `/account` to retrieve your
own ID, then share it with the sender. On `/`, enter the recipient ID and message.
Both sender and recipient can list and open the message. Only the sender can
delete it; neither can edit its recipient or body. Deletion removes access for
both. Self-registration alone does not establish tenant membership.

IDs are shown instead of names. This example provides private record access,
not email delivery or end-to-end encryption. Account eligibility errors disclose
only whether binding succeeded; exact-ID holders can test current eligibility.
