# animiq-nip76-tools
Tools for developing Private Channels [Nostr](https://github.com/fiatjaf/nostr) clients. Depends on [_@scure_](https://github.com/paulmillr/scure-base), [_@noble_](https://github.com/paulmillr/noble-hashes) & [_nostr-tools_](https://github.com/nbd-wtf/nostr-tools) packages.  If [NIP-76 Pull Request](https://github.com/nostr-protocol/nips/pull/413) is accepted, we will rename this package to "_nip76-tools_".

## Overview
- Each Private Channel message is encrypted with a unique key, signed with another unique key, and reveals no identifying information about the author or the intended recipient.
- Event signatures are verified through channel chainCode key derivation.
- Channel Keys are exchanged via event pointer strings, encrypted (by password or computed secret), which are the keys to a single nostrEvent called an _Invitation_.

## Installation

```bash
 npm install animiq-nip76-tools # or yarn add animiq-nip76-tools
```


## Usage

### Creating a nip76 wallet with a private key and a public key.   
Here we create the `pk` and `sk`, but you can use any key pair.   Currently only web storage is deomnstrated.  More storage types coming soon.

```js
import {generatePrivateKey, getPublicKey} from 'nostr-tools';
import {KeyStoreWebStorage} from 'animiq-nip76-tools';

let sk = generatePrivateKey() // `sk` is a hex string
let pk = getPublicKey(sk) // `pk` is a hex string

const wallet = await KeyStoreWebStorage.fromStorage({ ps, sk });
await wallet.save(sk);
```

### Creating New Private Channels

```js
let privateKey = await someMethodToGetTheProfilePrivateKey();

let channel = wallet.createChannel();
channel.content.name = 'My New Channel';
channel.content.about = 'Whatever we want';
let event = await wallet.documentsIndex.createEvent(channel, privateKey);

someMethodToSendTheEventToRelays(event);

```

### Creating a Text Note on a Private Channel

```js
import { PostDocument } from 'animiq-nip76-tools';

let privateKey = await someMethodToGetTheProfilePrivateKey();

let postDocument = new PostDocument();
postDocument.content = {
    'Hello World',
    pubkey: wallet.ownerPubKey,
    kind: nostrTools.Kind.Text
}
let event = await channel.dkxPost.createEvent(postDocument, privateKey);

someMethodToSendTheEventToRelays(event);
```

### Creating a Text Reply or Reaction to Private Channel Note

```js
import { PostDocument } from 'animiq-nip76-tools';

let privateKey = await someMethodToGetTheProfilePrivateKey();

let replyDocument = new PostDocument();
replyDocument.content = {
    'Hello Back',
    pubkey: wallet.ownerPubKey,
    kind: nostrTools.Kind.Text,  // or use nostrTools.Kind.Reaction
    tags: [['e', post.nostrEvent.id]]
}
let event = await channel.dkxPost.createEvent(replyDocument, privateKey);

someMethodToSendTheEventToRelays(event);
```

### Saving an Invitation for a public key

```js
let privateKey = await someMethodToGetTheProfilePrivateKey();

let invite = new Invitation();
invite.docIndex = channel.dkxInvite.documents.length + 1;
invite.content = {
    kind: NostrKinds.PrivateChannelInvitation,
    docIndex: invite.docIndex,
    for: '(pubkey-hex)',
    pubkey: channel.dkxPost.signingParent.nostrPubKey,
    signingParent: channel.dkxPost.signingParent,
    cryptoParent: channel.dkxPost.cryptoParent,
}
let event = await channel.dkxInvite.createEvent(invite, privateKey);

someMethodToSendTheEventToRelays(event);

let invitationTextToSend = await invite.getPointer();
```

### Saving an Invitation that uses a password

```js
let privateKey = await someMethodToGetTheProfilePrivateKey();

let invite = new Invitation();
invite.docIndex = channel.dkxInvite.documents.length + 1;
invite.content = {
    kind: NostrKinds.PrivateChannelInvitation,
    docIndex: invite.docIndex,
    password: 'the password',
    pubkey: channel.dkxPost.signingParent.nostrPubKey,
    signingParent: channel.dkxPost.signingParent,
    cryptoParent: channel.dkxPost.cryptoParent,
}
let event = await channel.dkxInvite.createEvent(invite, privateKey);

someMethodToSendTheEventToRelays(event);

let invitationTextToSend = await invite.getPointer();
```
### Reading an Invitation
(_NOTE: We are working to make this easier to implement._)

```js
import { nip19Extension, HDKIndex } from 'animiq-nip76-tools';

let pointer = await nip19Extension.decode(channelPointer, 'privateKeyHexOrPassword').data;

if ((pointer.type & nip19Extension.PointerType.FullKeySet) === nip19Extension.PointerType.FullKeySet) {
    // Unmanaged Invitation
    let signingParent = new HDKey({ publicKey: pointer.signingKey, chainCode: pointer.signingChain, version: Versions.nip76API1 });
    let cryptoParent = new HDKey({ publicKey: pointer.cryptoKey, chainCode: pointer.cryptoChain, version: Versions.nip76API1 });
    let invite = new Invitation();
    pointer.docIndex = -1;
    invite.pointer = pointer;
    invite.content = {
        kind: NostrKinds.PrivateChannelInvitation,
        pubkey: signingParent.nostrPubKey,
        docIndex: pointer.docIndex,
        signingParent,
        cryptoParent
    };

    channelIndex = new HDKIndex(HDKIndexType.Singleton, invite.content.signingParent!, invite.content.cryptoParent!);
    relayService.subscribe(
      [{ authors: [channelIndex.signingParent.nostrPubKey], kinds: [17761], limit: 1 }]
    );
    // the nostrEvent returned is the channel
} else {
    // Managed Invitation
    let inviteIndex = HDKIndex.fromChannelPointer(pointer);
    relayService.subscribe(
      [{ authors: [inviteIndex.signingParent.nostrPubKey], kinds: [17761], limit: 1 }]
    );
    // the nostrEvent returned is an invitation from which we can read the channel
}
```

### Reading Notes on a Channel
```js
relayService.subscribe([
      { '#e': [channel.dkxPost.eventTag], kinds: [17761], limit: length },
      { '#e': [channel.dkxRsvp.eventTag], kinds: [17761], limit: length },
    ]);

///events from the stream are then read like:
if (channel.dkxPost.eventTag === nostrEvent.tags[0][1]) {
    let post = await channel.dkxPost.readEvent(nostrEvent);
} else if (channel.dkxRsvp.eventTag === nostrEvent.tags[0][1]) {
    let rsvp = await channel.dkxRsvp.readEvent(nostrEvent);
}
```

## License

MIT
