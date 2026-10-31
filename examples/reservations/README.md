# Reservations

This trusted example reserves inventory at the product price reviewed by the
customer. Prices and totals are integer minor units; it does not process payments.

Build with the normal `noxide build --local` workflow, approve the generated
contract, then serve its bundle. Create two active accounts in the same tenant.
The product owner creates a product; another account can review the product and
submit a quantity from one to ten. The host decrements stock and creates the order
in one transaction. A changed product revision requires another review.

The approved order copies the product's price and currency, computes the total
with checked multiplication, and records the attempt's durable transaction time
and a fixed fifteen-minute duration. These timestamp fields are ordinary app
fields. The resource schema, action plan, and operation policies control their
writes; they are not host-protected creation metadata.

Cancellation takes no quantity input. It requires the order owner, checks that
the current order is pending, changes its status, and restores its saved quantity
to the referenced product. The host commits both changes and the receipt
together. Replaying the same submission recovers the receipt. A fresh cancellation
of an already cancelled order fails its guard without changing inventory.

Stock changes are declared only inside the reserve and cancel plans. There is no
standalone stock action or mutation import. Price, currency, and availability have
a separate owner-only edit form.

`expiry_manifest()` exposes a separate headless declaration for future service
admission. It uses the same pending transition and stored quantity, and adds an
expiry-time guard. It is not registered in the web app. Automatic expiry and
production service invocation remain unavailable until the service adapter is
implemented and approved.
