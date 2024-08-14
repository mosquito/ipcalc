class History {
  constructor(dbName = 'HistoryDatabase', dbVersion = 1) {
    this.dbName = dbName;
    this.dbVersion = dbVersion;
    this.db = null;
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);

      request.onerror = event => reject(`Database error: ${event.target.error}`);

      request.onsuccess = event => {
        this.db = event.target.result;
        resolve();
      };

      request.onupgradeneeded = event => {
        this.db = event.target.result;

        const historyStore = this.db.createObjectStore('history', {
          keyPath: 'id',
          autoIncrement: true
        });
        historyStore.createIndex('value', 'value', { unique: true });
        historyStore.createIndex('count', 'count', { unique: false });

        const lastStore = this.db.createObjectStore('last', { keyPath: 'id' });
      };
    });
  }

  async store(value) {
    if (!value.trim()) {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['history', 'last'], 'readwrite');
      const historyStore = transaction.objectStore('history');
      const lastStore = transaction.objectStore('last');

      const index = historyStore.index('value');
      const request = index.get(value);

      request.onsuccess = event => {
        const existingRecord = event.target.result;
        if (existingRecord) {
          existingRecord.count += 1;
          historyStore.put(existingRecord);
          this.updateLast(value, lastStore);
          resolve(existingRecord.id);
        } else {
          const addRequest = historyStore.add({ value, count: 1 });
          addRequest.onsuccess = event => {
            this.updateLast(value, lastStore);
            resolve(event.target.result);
          };
        }
      };

      request.onerror = event => reject(`Error checking existing data: ${event.target.error}`);
    });
  }

  updateLast(value, lastStore) {
    const putRequest = lastStore.put({ id: 1, value });

    putRequest.onerror = event => console.error(`Error updating last: ${event.target.error}`);
  }

  async list(limit = Infinity) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['history'], 'readonly');
      const historyStore = transaction.objectStore('history');
      const index = historyStore.index('count');
      const request = index.openCursor(null, 'prev');

      const results = [];

      request.onerror = event => reject(`Error listing data: ${event.target.error}`);

      request.onsuccess = event => {
        const cursor = event.target.result;
        if (cursor && results.length < limit) {
          results.push({ value: cursor.value.value, count: cursor.value.count });
          cursor.continue();
        } else {
          resolve(results);
        }
      };
    });
  }

  async getLast() {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['last'], 'readonly');
      const lastStore = transaction.objectStore('last');
      const request = lastStore.get(1);

      request.onerror = event => reject(`Error getting last: ${event.target.error}`);

      request.onsuccess = event => {
        if (request.result) {
          resolve({ value: request.result.value });
        } else {
          resolve(null);
        }
      };
    });
  }
}


class Address {
    constructor(ip, prefixLength) {
        switch (typeof ip) {
            case 'string':
                this.address = this.toInteger(ip);
                break;
            case 'bigint':
                this.address = ip;
                break;
            case "number":
                this.address = BigInt(ip);
                break;
            default:
                throw new Error("Invalid IP address format");
        }
        this.prefixLength = BigInt(prefixLength);
    }

    toBinary() {
        return this.address.toString(2).padStart(Number(this.totalBits), '0');
    }

    get broadcastAddress() {
        if (this.prefixLength === this.totalBits) return this;
        return new this.constructor((
            this.address | (
            ~this.prefixToMask(this.prefixLength, this.totalBits) &
            this.prefixToMask(this.totalBits, this.totalBits)
        )), this.prefixLength);
    }

    get networkAddress() {
        const mask = this.prefixToMask(this.prefixLength, this.totalBits);
        const networkAddr = this.address & mask;
        return new this.constructor(networkAddr, this.prefixLength);
    }

    get firstAddress() {
        if (this.prefixLength === this.totalBits) return this;
        return new this.constructor(
            this.networkAddress.address + 1n,
            this.prefixLength
        );
    }

    get lastAddress() {
        if (this.prefixLength === this.totalBits) return this;
        return new this.constructor(
            this.broadcastAddress.address - 1n,
            this.prefixLength
        );
    }

    toInteger(ip) {
        throw new Error("Method 'toInteger(ip)' must be implemented.");
    }

    toString() {
        throw new Error("Method 'toString(int)' must be implemented.");
    }

    toCompleteString() {
        throw new Error("Method 'toCompleteString(int)' must be implemented.");
    }

    prefixToMask(prefixLength, totalBits) {
        if (prefixLength === 0) return 0n;
        if (prefixLength === totalBits) return (1n << BigInt(totalBits)) - 1n;
        const shift = BigInt(totalBits - prefixLength);
        return ((1n << BigInt(totalBits)) - 1n) ^ ((1n << shift) - 1n);
    }

    get length() {
        return 1n << (this.totalBits - this.prefixLength);
    }

    get hexId() {
        return '0x' + this.address.toString(16).padStart(Number(this.totalBits / 4n), '0');
    }

    get base85Id() {
        const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
        let int = this.address;
        let result = '';
        while (int > 0) {
            result = chars[int % 85n] + result;
            int = int / 85n;
        }
        return result;
    }

    get base64Id() {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let int = this.address;
        let result = '';
        while (int > 0) {
            result = chars[int % 64n] + result;
            int = int / 64n;
        }
        return result;
    }

    get base32Id() {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let int = this.address;
        let result = '';
        while (int > 0) {
            result = chars[int % 32n] + result;
            int = int / 32n;
        }
        return result;
    }

    get totalBits() {
        throw new Error("Getter 'totalBits' must be implemented.");
    }

    get arpaFormat() {
        throw new Error("Getter 'getArpaFormat()' must be implemented.");
    }

    get addressTypes() {
        throw new Error("Getter 'addressTypes' must be implemented.");
    }

    get type() {
        for (const [type, start, end] of this.addressTypes) {
            if (start <= this.address && end >= this.address) return type;
        }
        return "Unknown";
    }

    nat64() {
        throw new Error("Method 'nat64' must be implemented.");
    }

}

class IPv4 extends Address {
    static TYPE_LIST = [
        ["Private", "10.0.0.0", "10.255.255.255"],
        ["Private", "172.16.0.0", "172.31.255.255"],
        ["Private", "192.168.0.0", "192.168.255.255"],
        ["Loopback", "127.0.0.0", "127.255.255.255"],
        ["Link-local", "169.254.0.0", "169.254.255.255"],
        ["Multicast", "224.0.0.0", "239.255.255.255"],
        ["Broadcast", "255.255.255.255", "255.255.255.255"],
        ["Shared Address Space", "100.64.0.0", "100.127.255.255"],
        ["Global Unicast", "0.0.0.0", "223.255.255.255"]
    ].map(([type, start, end]) => [type, IPv4.toBigInt(start), IPv4.toBigInt(end)]);

    get addressTypes() {
        return IPv4.TYPE_LIST;
    }

    get totalBits() {
        return 32n;
    }

    toInteger(ip) {
        return ip.split('.').reduce((int, octet) => int * 256n + BigInt(octet), 0n);
    }

    toString() {
        return [
            Number(this.address >> 24n & 255n),
            Number(this.address >> 16n & 255n),
            Number(this.address >> 8n & 255n),
            Number(this.address & 255n)
        ].join('.');
    }

    toCompleteString() {
        let octets = [
            (this.address >> 24n & 255n).toString().padStart(3, '0'),
            (this.address >> 16n & 255n).toString().padStart(3, '0'),
            (this.address >> 8n & 255n).toString().padStart(3, '0'),
            (this.address & 255n).toString().padStart(3, '0')
        ];

        let prefixLength = Number(this.prefixLength);
        let fullAddress = octets.join('.');
        let splitIndex;

        switch (prefixLength) {
            case 32:
                splitIndex = 15;
                break;
            case 31:
                splitIndex = 14;
                break;
            case 30:
                splitIndex = 13;
                break;
            case 29:
                splitIndex = 13;
                break;
            case 28:
                splitIndex = 13;
                break;
            case 27:
                splitIndex = 13;
                break;
            case 26:
                splitIndex = 13;
                break;
            case 25:
                splitIndex = 11;
                break;
            case 24:
                splitIndex = 11;
                break;
            case 23:
                splitIndex = 10;
                break;
            case 22:
                splitIndex = 10;
                break;
            case 21:
                splitIndex = 9;
                break;
            case 20:
                splitIndex = 9;
                break;
            case 19:
                splitIndex = 9;
                break;
            case 18:
                splitIndex = 8;
                break;
            case 17:
                splitIndex = 8;
                break;
            case 16:
                splitIndex = 8;
                break;
            case 15:
                splitIndex = 6;
                break;
            case 14:
                splitIndex = 5;
                break;
            case 13:
                splitIndex = 5;
                break;
            case 12:
                splitIndex = 5;
                break;
            case 11:
                splitIndex = 5;
                break;
            case 10:
                splitIndex = 5;
                break;
            case 9:
                splitIndex = 4;
                break;
            case 8:
                splitIndex = 4;
                break;
            case 7:
                splitIndex = 2;
                break;
            case 6:
                splitIndex = 2;
                break;
            case 5:
                splitIndex = 2;
                break;
            default:
                splitIndex = 0;
        }

        let networkPart = fullAddress.slice(0, splitIndex);
        let addressPart = fullAddress.slice(splitIndex);

        let result = `<span class="network">${networkPart}</span><span class="address">${addressPart}</span>`;

        return `${result}/${this.prefixLength}`;
    }

    get arpaFormat() {
        return this.toString().split('.').reverse().join('.') + '.in-addr.arpa';
    }

    static toBigInt(ip) {
        return ip.split('.').reduce((int, octet) => int * 256n + BigInt(octet), 0n);
    }

    nat64() {
        const nat64 = new IPv6(nat64Prefix.address + this.address, 96);
        return `${nat64.compact()}/${nat64.prefixLength}`;
    }

    toBinary() {
        let binary = super.toBinary();
        return binary.match(/.{8}/g).join(' ');
    }
}

class IPv6 extends Address {
    static TYPE_LIST = [
        ["NAT64", "64:ff9b::", "64:ff9b::ffff:ffff"],
        ["Global Unicast", "2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Link-local", "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Unique Local", "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Multicast", "ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Loopback", "::1", "::1"],
        ["Reserved", "::", "::"],
        ["Reserved", "::ffff:0:0", "::ffff:ffff:ffff"],
        ["Reserved", "4000::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
    ].map(([type, start, end]) => [type, IPv6.toBigInt(start), IPv6.toBigInt(end)]);

    get addressTypes() {
        return IPv6.TYPE_LIST;
    }

    get totalBits() {
        return 128n;
    }

    expand(ip) {
        const parts = ip.split('::');
        let head = parts[0].split(':').map(part => part || '0');
        let tail = parts[1] ? parts[1].split(':').map(part => part || '0') : [];
        let middle = Array(8 - head.length - tail.length).fill('0');
        return [...head, ...middle, ...tail].join(':');
    }

    compact() {
        let ip = this.toString();
        let parts = ip.split(':');
        let zeroGroups = [];
        let currentGroup = [];

        for (let i = 0; i < parts.length; i++) {
            if (parts[i] === '0') {
                currentGroup.push(i);
            } else {
                if (currentGroup.length > 0) {
                    zeroGroups.push(currentGroup);
                    currentGroup = [];
                }
            }
        }
        if (currentGroup.length > 0) {
            zeroGroups.push(currentGroup);
        }

        let longestGroup = zeroGroups.reduce((longest, group) => group.length > longest.length ? group : longest, []);

        if (longestGroup.length > 0) {
            parts.splice(longestGroup[0], longestGroup.length, '');
        }

        parts = parts.map(part => part.replace(/^0{1,3}/, ''));

        let compactedIp = parts.join(':').replace(/:{2,}/, '::');

        if (compactedIp.endsWith(':')) {
            compactedIp += ':';
        }
        return compactedIp;
    }

    toInteger(ip) {
        ip = this.expand(ip);
        return ip.split(':').reduce((int, hextet) => int * 65536n + BigInt(parseInt(hextet, 16)), 0n);
    }

    toString() {
        let hexString = this.address.toString(16).padStart(32, '0');
        let hextets = [];
        for (let i = 0; i < 32; i += 4) {
            hextets.push(hexString.slice(i, i + 4).replace(/^0{1,3}/, ''));
        }
        let zeroGroups = [];
        let currentGroup = [];

        for (let i = 0; i < hextets.length; i++) {
            if (hextets[i] === '0') {
                currentGroup.push(i);
            } else {
                if (currentGroup.length > 0) {
                    zeroGroups.push(currentGroup);
                    currentGroup = [];
                }
            }
        }
        if (currentGroup.length > 0) {
            zeroGroups.push(currentGroup);
        }

        let longestGroup = zeroGroups.reduce((longest, group) => group.length > longest.length ? group : longest, []);

        if (longestGroup.length > 0) {
            hextets.splice(longestGroup[0], longestGroup.length, '');
        }

        hextets = hextets.map(part => part.replace(/^0{1,3}/, ''));

        let compactedIp = hextets.join(':').replace(/:{2,}/, '::');

        if (compactedIp.endsWith(':')) {
            compactedIp += ':';
        }
        return compactedIp;
    }

    toCompleteString() {
        let hexString = this.address.toString(16).padStart(32, '0');
        let hextets = [];
        for (let i = 0; i < 32; i += 4) {
            hextets.push(hexString.slice(i, i + 4));
        }
        let prefixLength = Number(this.prefixLength);

        let result = '<span class="network">';
        let networkBitsLeft = prefixLength;

        for (let i = 0; i < 8; i++) {
            if (i > 0) result += ':';

            if (networkBitsLeft >= 16) {
                result += hextets[i];
                networkBitsLeft -= 16;
            } else if (networkBitsLeft > 0) {
                let networkPart = hextets[i].slice(0, Math.ceil(networkBitsLeft / 4));
                let addressPart = hextets[i].slice(Math.ceil(networkBitsLeft / 4));
                result += `${networkPart}</span><span class="address">${addressPart}`;
                networkBitsLeft = 0;
            } else {
                if (networkBitsLeft === 0) {
                    result += '</span><span class="address">';
                    networkBitsLeft = -1;
                }
                result += hextets[i];
            }
        }

        result += '</span>';

        return `${result}/${prefixLength}`;
    }

    get arpaFormat() {
        let reversed = this.toString(this.address).split(':').map(part => part.padStart(4, '0')).join('').split('').reverse().join('.');
        return `${reversed}.ip6.arpa`;
    }

    get type() {
        const networkAddress = this.networkAddress.address;
        const broadcastAddress = this.broadcastAddress.address;
        for (const [type, start, end] of IPv6.TYPE_LIST) {
            if (networkAddress >= start && broadcastAddress <= end) {
                return type;
            }
        }
        return "Unknown";
    }

    static toBigInt(ip) {
        ip = IPv6.prototype.expand(ip);
        return ip.split(':').reduce((int, hextet) => int * 65536n + BigInt(parseInt(hextet, 16)), 0n);
    }

    nat64() {

        if (this.type !== 'NAT64') return 'Not applicable';
        const ipv4Address = this.address - nat64Prefix.address;
        return new IPv4(ipv4Address, 32).toString();
    }

    toBinary() {
        let binary = super.toBinary();
        return binary.match(/.{16}/g).join(' ');
    }
}

const nat64Prefix = new IPv6('64:ff9b::', 96);

function parseIp(input) {
    let [ip, prefixLength] = input.split('/');
    if (!prefixLength) {
        prefixLength = ip.includes(':') ? 64 : 24;
    } else {
        prefixLength = parseInt(prefixLength, 10);
    }

    if (ip.includes(':')) {
        return new IPv6(ip, prefixLength);
    } else if (ip.includes('.')) {
        return new IPv4(ip, prefixLength);
    } else {
        throw new Error('Invalid IP address format');
    }
}

function displayResults(input) {
    let ipObj = parseIp(input);
    setAddressInURL(input);

    let resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `
        <table>
            <tr>
                <th>Field</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Address</td>
            <td data-type="address">
                <a onclick="copy(this)" class="copy">${ipObj.toCompleteString()}</a>
            </td>
            </tr>
            <tr>
                <td>Type</td>
                <td data-type="type">
                    <a onclick="copy(this)" class="copy">${ipObj.type}</a>
                </td>
            </tr>
            <tr>
                <td>Network</td>
                <td data-type="network">
                    <a onclick="copy(this)" class="copy">${ipObj.networkAddress.toCompleteString()}</a>
                </td>
            </tr>
            <tr>
                <td>Broadcast</td>
                <td data-type="address">
                    <a onclick="copy(this)" class="copy">${ipObj.broadcastAddress.toCompleteString()}</a>
                </td>
            </tr>
            <tr>
                <td>Network range</td>
                <td data-type="range">
                    <a onclick="copy(this)" class="copy"><span class="ip-range">${ipObj.networkAddress.toCompleteString()}</span> <span>${ipObj.broadcastAddress.toCompleteString()}</span></a>
                </td>
            </tr>
            <tr>
                <td>Hosts Addresses</td>
                <td data-type="range">
                    <a onclick="copy(this)" class="copy"><span class="ip-range">${ipObj.firstAddress.toCompleteString()}</span> <span>${ipObj.lastAddress.toCompleteString()}</span></a>
                </td>
            </tr>
            <tr>
                <td>Total IP addresses</td>
                <td data-type="number">
                    <a onclick="copy(this)" class="copy">${ipObj.length.toString()}</a>
                </td>
            </tr>
            <tr>
                <td>Integer ID</td>
                <td data-type="id">
                    <a onclick="copy(this)" class="copy">${ipObj.address.toString()}</a>
                </td>
            </tr>
            <tr>
                <td>Hexadecimal ID</td>
                <td data-type="id">
                    <a onclick="copy(this)" class="copy">${ipObj.hexId}</a>
                </td>
            </tr>
            <tr>
                <td>Base 32 ID</td>
                <td data-type="id">
                    <a onclick="copy(this)" class="copy">${ipObj.base32Id}</a>
                </td>
            </tr>
            <tr>
                <td>Base 64 ID</td>
                <td data-type="id">
                    <a onclick="copy(this)" class="copy">${ipObj.base64Id}</a>
                </td>
            </tr>
            <tr>
                <td>Base 85 ID</td>
                <td data-type="id">
                    <a onclick="copy(this)" class="copy">${ipObj.base85Id}</a>
                </td>
            </tr>
            <tr>
                <td>arpa Format</td>
                <td data-type="address">
                    <a onclick="copy(this)" class="copy">${ipObj.arpaFormat}</a>
                </td>
            </tr>
            <tr>
                <td>Nat64</td>
                <td data-type="address">
                    <a onclick="copy(this)" class="copy">${ipObj.nat64()}</a>
                </td>
            </tr>
            <tr>
                <td>Check IP in subnet</td>
                <td>
                    <input type="text" id="checkIpInput" placeholder="Enter IP to check">
                    <button id="checkIpButton">Check</button>
                    <span id="checkResult"></span>
                </td>
            </tr>
        </table>
    `;

    document.getElementById('checkIpInput').addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            checkIpInSubnet(ipObj, document.getElementById('checkIpInput').value.trim());
        }
    });

    document.getElementById('checkIpButton').addEventListener('click', function() {
        checkIpInSubnet(ipObj, document.getElementById('checkIpInput').value.trim());
    });

    history.store(input).then(updateHistory);
}

function checkIpInSubnet(networkObj, ipToCheck) {
    if (!ipToCheck) {
        showCheckResult('Please enter an IP address to check', 'warning');
        return;
    }

    try {
        const ipObj = parseIp(ipToCheck);

        if (networkObj.constructor !== ipObj.constructor) {
            throw new Error("IP version mismatch");
        }

        const isInSubnet = ipObj.address >= networkObj.networkAddress.address && ipObj.address <= networkObj.broadcastAddress.address;

        if (isInSubnet) {
            showCheckResult(`${ipToCheck} is in the subnet`, 'success');
        } else {
            showCheckResult(`${ipToCheck} is not in the subnet`, 'error');
        }
    } catch (error) {
        showCheckResult(`Error: ${error.message}`, 'error');
    }
}

function showCheckResult(message, status) {
    const resultSpan = document.getElementById('checkResult');
    resultSpan.classList.remove('visible', 'success', 'error', 'warning');

    setTimeout(() => {
        resultSpan.textContent = message;
        resultSpan.classList.add('visible', status);
    }, 50);
}

function copy(element) {
    let text = element.textContent;
    navigator.clipboard.writeText(text).then(() => {
        element.classList.add('copied');
        element.style.opacity = 1;
        element.style.visibility = 'visible';
        setTimeout(() => { element.classList.remove('copied'); }, 1000);
    });
}

function setAddressInURL(address) {
    const url = new URL(window.location);
    url.searchParams.set('address', address);
    window.history.pushState({}, '', url);
}

function getAddressFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('address');
}

document.getElementById('ipForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const input = document.getElementById('ipAddress');
    const formGroup = input.closest('.form-group');

    const existingTooltip = formGroup.querySelector('.error-tooltip');
    if (existingTooltip) {
        existingTooltip.remove();
    }
    input.classList.remove('error');

    function showErrorTooltip(message) {
        const tooltip = document.createElement('span');
        tooltip.className = 'error-tooltip';
        tooltip.textContent = message;
        formGroup.appendChild(tooltip);
        input.classList.add('error');

        const inputRect = input.getBoundingClientRect();
        const formGroupRect = formGroup.getBoundingClientRect();
        tooltip.style.left = `${inputRect.left - formGroupRect.left + inputRect.width / 2}px`;
        tooltip.style.top = `${inputRect.top - formGroupRect.top - 10}px`;

        setTimeout(() => {
            tooltip.remove();
            input.classList.remove('error');
        }, 3000);
    }

    try {
        const ipObj = parseIp(input.value);
        displayResults(input.value);
    } catch (error) {
        showErrorTooltip(error.message);
    }
});

const history = new History();

function fillForm(value) {
    value = value || this.value;
    if (!value) return;

    document.getElementById('ipAddress').value = value;
    displayResults(value);
}

async function main() {
    await history.init();

    let urlAddress = getAddressFromURL();
    if (!urlAddress) {
        let last = await history.getLast();
        if (last !== null) urlAddress = last.value
    }

    const myAddresses = await Promise.all([myIPv4address(), myIPv6address()]);
    if (!urlAddress) {
        for (const address of myAddresses) {
            if (address) {
                urlAddress = address;
                break;
            }
        }
    }

    fillForm(urlAddress);

    document.getElementById('ipAddress').focus()

    const examples = document.getElementById('examples');
    for (const address of myAddresses) {
        if (address) examples.innerHTML += `<li><a onclick="fillForm('${address}')"><code>${address}</code> (current Address)</a></li>`;
    }
    examples.innerHTML += `<li><a onclick="fillForm('10.0.0.0/8')">Complete IPv4 address <code>10.0.0.0/8</code></a></li>`;
    examples.innerHTML += `<li><a onclick="fillForm('2000::/3')">Complete IPv6 address with netmask <code>2000::/3</code></a></li>`;
    examples.innerHTML += `<li><a onclick="fillForm('192.168.1.0')"><code>192.168.1.0</code> (default /24)</a></li>`;
    examples.innerHTML += `<li><a onclick="fillForm('2001:db8:1234::5')"><code>2001:db8:1234::5</code> (default /64)</a></li>`;
}


async function updateHistory() {
    let results = await history.list(50);
    if (results.length === 0) return;
    let historyDiv = document.getElementById('history');
    historyDiv.innerHTML = `
        <h2>History</h2>
        <div class="history-scroll">
            <ul>
                ${results.map(result => `<li><a onclick="fillForm(this.text)">${result.value}</a></li>`).join('')}
            </ul>
        </div>
    `;
}

async function myIPv4address() {
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        return data.ip;
    } catch (error) {
        console.error('Error fetching IPv4 address:', error);
        return null;
    }
}

async function myIPv6address() {
    try {
        const response = await fetch('https://api6.ipify.org?format=json');
        const data = await response.json();
        return data.ip;
    } catch (error) {
        console.error('Error fetching IPv4 address:', error);
        return null;
    }
}

document.addEventListener('DOMContentLoaded', main);
