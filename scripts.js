document.addEventListener('DOMContentLoaded', () => {
    const generateForm = document.getElementById('generateForm');
    const connectForm = document.getElementById('connectForm');
    const sendForm = document.getElementById('sendForm');

    generateForm.addEventListener('submit', generate);
    connectForm.addEventListener('submit', connect);
    sendForm.addEventListener('submit', send);

    loadProjects();
});

function loadProjects() {
    fetch('projects.json')
        .then(response => response.json())
        .then(data => {
            projects = data;
            displayProjects(projects);
        })
        .catch(error => console.error('Error loading projects:', error));
}

function displayProjects(projects) {
    const projectContainer = document.getElementById('project_results');
    projectContainer.innerHTML = '';
    projects.forEach(project => {
        const projectDiv = document.createElement('div');
        projectDiv.classList.add('project-card');
        projectDiv.innerHTML = `
          <p><strong>Project Identifier:</strong> ${project.projectIdentifier}</p>
          <p><strong>Founder Key:</strong> ${project.founderKey}</p>
          <p><strong>Created On Block:</strong> ${project.createdOnBlock}</p>
          <p><strong>Transaction ID:</strong> ${project.trxId}</p>
        `;
        projectDiv.addEventListener('click', () => {
            fetchMetadata(project.nostrPubKey);
        });
        projectContainer.appendChild(projectDiv);
    });
}

function fetchMetadata(pubkey) {
    const relayUrl = getRelayUrl();
    const socket = new WebSocket(relayUrl);

    socket.addEventListener('open', () => {
        const metadataFilter = { authors: [pubkey], kinds: [0] };
        const metadataSubscription = ["REQ", pubkey, metadataFilter];
        socket.send(JSON.stringify(metadataSubscription));
    });

    socket.addEventListener('message', event => {
        const [type, subId, eventData] = JSON.parse(event.data);
        if (type === 'EVENT' && eventData.kind === 0) {
            handleMetadataEvent(eventData.pubkey, eventData.content);
        }
    });

    socket.addEventListener('close', () => {
        console.log("Disconnected from relay");
    });
}

function handleMetadataEvent(pubkey, content) {
    const metadata = JSON.parse(content);
    const project = projects.find(project => project.nostrPubKey === pubkey);
    if (project) {
        project.metadata = metadata;
        displayProject(project);
    }
}

function displayProject(project) {
    const results = document.getElementById('search_results');
    results.innerHTML = `
      <div class="profile-container">
        <img class="profile-banner" src="${project.metadata.banner}" alt="Banner">
        <img class="profile-picture" src="${project.metadata.picture}" alt="Profile Picture">
        <div class="profile-details">
          <h1>${project.metadata.name}</h1>
          <p>${project.metadata.about}</p>
        </div>
      </div>
      <div class="comments-section">
        <h2>Comments</h2>
        ${project.metadata.comments ? project.metadata.comments.map(comment => `
          <div class="comment">
            <p><strong>${comment.author}:</strong> ${comment.text}</p>
          </div>
        `).join('') : '<p>No comments yet.</p>'}
        <div class="text-box">
          <textarea id="new_comment" placeholder="Add a comment" rows="3"></textarea>
        </div>
        <button onclick="addComment('${project.founderKey}')" class="speak-button">Submit</button>
      </div>
    `;
}

function addComment(founderKey) {
    const newComment = document.getElementById('new_comment').value;
    console.log(`New comment for ${founderKey}: ${newComment}`);
// TODO
}

function getPublicKey() {
    return document.getElementById('public_key').value;
}

function setPublicKey(key) {
    document.getElementById('public_key').value = key;
    localStorage.setItem('public_key', key);
}

function getPrivateKey() {
    return document.getElementById('private_key').value;
}

function setPrivateKey(key) {
    document.getElementById('private_key').value = key;
    localStorage.setItem('private_key', key);
}

function getRelayUrl() {
    return document.getElementById('relay_url').value;
}

function getDestinationPublicKey() {
    return document.getElementById('public_key_destination').value;
}

function getMessageToSend() {
    return document.getElementById('message').value;
}

function clearMessageToSend() {
    document.getElementById('message').value = "";
}

function clearMessages() {
    messages = [];

    var table = document.getElementById('messages');
    table.innerHTML = "";
}

function appendHeader(row, text) {
    var header = document.createElement("th");
    header.textContent = text;
    row.appendChild(header);
}

function appendMessage(content, pubkey, created_at, tags) {
    messages.push(
        {
            'date': created_at,
            'from': pubkey,
            'to': getDestinationPublicKeyFromTags(tags),
            'message': content
        }
    );
    messages = messages.sort((a, b) => (a.date < b.date) ? 1 : -1);

    var table = document.getElementById('messages');
    table.innerHTML = "";
    var headerRow = table.insertRow();
    appendHeader(headerRow, "Date");
    appendHeader(headerRow, "From");
    appendHeader(headerRow, "To");
    appendHeader(headerRow, "Message");

    messages.forEach(element => {
        var row = table.insertRow();
        insertCell(row, dateToString(element.date));
        insertCell(row, prettyFormatKey(element.from), element.from);
        insertCell(row, prettyFormatKey(element.to), element.to);
        insertCell(row, element.message);
    });
}

function insertCell(row, text, mouseovertext) {
    var cell = row.insertCell();
    appendPreTag(cell, text, mouseovertext);
}

function appendPreTag(cell, text, mouseovertext) {
    var pre = document.createElement('pre');
    pre.textContent = text;
    cell.appendChild(pre);
    var preMouseOverText = document.createElement('pre');
    preMouseOverText.textContent = mouseovertext;
    preMouseOverText.hidden = true;
    cell.appendChild(preMouseOverText);
    if (mouseovertext) {
        cell.addEventListener("mouseover", function (event) {
            preMouseOverText.hidden = false;
            pre.hidden = true;
        });
        cell.addEventListener("mouseout", function (event) {
            preMouseOverText.hidden = true;
            pre.hidden = false;
        });
    }
}

var socket;
var messages = [];
var projects = [];

function generate() {
    var keypair = bitcoinjs.ECPair.makeRandom();
    var privKey = keypair.privateKey.toString("hex");
    var pubKey = keypair.publicKey.toString("hex");
    pubKey = pubKey.substring(2);

    setPublicKey(pubKey);
    setPrivateKey(privKey);
}

function disconnect() {
    if (!socket) return;

    socket.close();
}

function connect() {
    if (getPublicKey().length < 1 || getPrivateKey().length < 1) {
        alert("Generate or input public/private keys.");
        return;
    }

    clearMessages();

    var relayUrl = getRelayUrl();
    if (socket) socket.close();
    socket = new WebSocket(relayUrl);

    socket.addEventListener('message', async function (message) {
        var [type, subId, event] = JSON.parse(message.data);
        if (!event) return;
        console.log('Event:', event);
        var { kind, content, tags, pubkey, created_at, id } = event || {};
        console.log('Event (Nostr Gateway):', "https://nostr.com/e/" + id);
        if (kind === 1) {
            appendMessage(content, pubkey, created_at, tags);
        } else if (kind === 4) {
            if (pubkey == getPublicKey()) {
                // I'm the sender of this encrypted direct message
                // Decrypt content using private key and destination public key
                var destinationPubKey = getDestinationPublicKeyFromTags(tags);
                content = await decrypt(getPrivateKey(), destinationPubKey, content);
            } else {
                // I'm the destination of this encrypted direct message
                // Decrypt content using my private key and the sender public key
                content = await decrypt(getPrivateKey(), pubkey, content);
            }
            appendMessage(content, pubkey, created_at, tags);
        } else if (kind === 0) {
            // Metadata event
            handleMetadataEvent(pubkey, content);
        }
    });

    socket.addEventListener('close', async function (e) {
        console.log("Disconnected");
        document.getElementById('connectButton').hidden = false;
        document.getElementById('disconnectButton').hidden = true;
    });

    socket.addEventListener('open', async function (e) {
        console.log("Connected to " + relayUrl);
        console.log("Events (Nostr Gateway):", "https://nostr.com/p/" + getPublicKey());
        document.getElementById('connectButton').hidden = true;
        document.getElementById('disconnectButton').hidden = false;

        var subId = bitcoinjs.ECPair.makeRandom().privateKey.toString("hex");
        var authorFilter = { "authors": [getPublicKey()] };
        var edmFilter = { "#p": [getPublicKey()] };
        var subscription = ["REQ", subId, authorFilter, edmFilter];
        console.log('Subscription:', subscription);
        socket.send(JSON.stringify(subscription));

        // Fetch metadata for all projects
        await loadProjects();
        projects.forEach(project => {
            var metadataFilter = { "authors": [project.nostrPubKey], "kinds": [0] };
            var metadataSubscription = ["REQ", subId, metadataFilter];
            socket.send(JSON.stringify(metadataSubscription));
        });
    });
}

function getDestinationPublicKeyFromTags(tags) {
    var i; for (i = 0; i < tags.length; i++) {
        if (tags[i][0] === "p") {
            return tags[i][1];
        }
    }
    return "";
}

function send() {
    if (!socket) {
        alert("You must connect to a relay.");
        return;
    }
    if (getMessageToSend().length < 1) {
        alert("Write a message.");
        return;
    }

    var destinationPubKey = getDestinationPublicKey();
    if (destinationPubKey) {
        sendEncryptedDirectMessage(getPrivateKey(), getPublicKey(), destinationPubKey, getMessageToSend());
    } else {
        sendTextNote(getPrivateKey(), getPublicKey(), getMessageToSend());
    }
    clearMessageToSend();
}

// https://github.com/nostr-protocol/nips/blob/master/01.md#basic-event-kinds
async function sendTextNote(privkey, pubkey, text) {
    var event = {
        "content": text,
        "created_at": Math.floor(Date.now() / 1000),
        "kind": 1,
        "tags": [],
        "pubkey": pubkey
    };
    var signedEvent = await getSignedEvent(event, privkey);
    console.log('Signed Event:', signedEvent);
    socket.send(JSON.stringify(["EVENT", signedEvent]));
}

// https://github.com/nostr-protocol/nips/blob/master/04.md
async function sendEncryptedDirectMessage(privkey, pubkey, destpubkey, text) {
    var encrypted = encrypt(privkey, destpubkey, text)
    var event = {
        "content": encrypted,
        "created_at": Math.floor(Date.now() / 1000),
        "kind": 4,
        "tags": [['p', destpubkey]],
        "pubkey": pubkey
    };
    var signedEvent = await getSignedEvent(event, privkey);
    console.log('Signed Event:', signedEvent);
    socket.send(JSON.stringify(["EVENT", signedEvent]));
}

async function getSignedEvent(event, privateKey) {
    var { schnorr } = nobleSecp256k1;
    var sha256 = bitcoinjs.crypto.sha256;
    var eventData = JSON.stringify([
        0,
        event['pubkey'],
        event['created_at'],
        event['kind'],
        event['tags'],
        event['content']
    ]);
    event.id = sha256(eventData).toString('hex');
    event.sig = await schnorr.sign(event.id, privateKey);
    return event;
}

function hexToBytes(hex) {
    return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function bytesToHex(bytes) {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

function base64ToHex(str) {
    var raw = atob(str);
    var result = '';
    var i; for (i = 0; i < raw.length; i++) {
        var hex = raw.charCodeAt(i).toString(16);
        result += (hex.length === 2 ? hex : '0' + hex);
    }
    return result;
}

function encrypt(privkey, pubkey, text) {
    var key = nobleSecp256k1.getSharedSecret(privkey, '02' + pubkey, true).substring(2);
    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    var cipher = browserifyCipher.createCipheriv(
        'aes-256-cbc',
        hexToBytes(key),
        iv
    );
    var encryptedMessage = cipher.update(text, "utf8", "base64");
    emsg = encryptedMessage + cipher.final("base64");
    var uint8View = new Uint8Array(iv.buffer);
    return emsg + "?iv=" + btoa(String.fromCharCode.apply(null, uint8View));
}

function decrypt(privkey, pubkey, ciphertext) {
    var [emsg, iv] = ciphertext.split("?iv=");
    var key = nobleSecp256k1.getSharedSecret(privkey, '02' + pubkey, true).substring(2);
    var decipher = browserifyCipher.createDecipheriv(
        'aes-256-cbc',
        hexToBytes(key),
        hexToBytes(base64ToHex(iv))
    );
    var decryptedMessage = decipher.update(emsg, "base64");
    return decryptedMessage + decipher.final("utf8");
}

function dateToString(unixTimestamp) {
    return new Date(unixTimestamp * 1000).toLocaleString();
}

function prettyFormatKey(key) {
    if (key) {
        return key.slice(0, 4) + "..." + key.slice(-4);
    } else {
        return "PUBLIC";
    }
}
