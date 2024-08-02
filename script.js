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

    get broadcastAddress() {
        return new this.constructor((
            this.address | (
                ~this.prefixToMask(this.prefixLength, this.totalBits) &
                this.prefixToMask(this.totalBits, this.totalBits)
            )
        ), this.prefixLength);
    }

    get networkAddress() {
        return new this.constructor(
            this.address & this.prefixToMask(this.prefixLength, this.totalBits),
            this.prefixLength
        );
    }

    get firstAddress() {
        return new this.constructor(
            this.networkAddress.address + 1n,
            this.prefixLength
        );
    }

    get lastAddress() {
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

    prefixToMask(prefixLength, totalBits) {
        return (1n << totalBits) - (1n << (totalBits - prefixLength));
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
        // removes zeros octets from middle and replace it with '::'
        let ip = this.toString();
        return ip.replace(/(^|:)0{1,4}(?=(:|$))/g, '::').replace(/:{2,}/, '::');
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
        return hextets.join(':').replace(/:{2,}/, '::');
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
                <a onclick="copy(this)" class="copy">${ipObj.toString()}/${ipObj.prefixLength}</a>
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
                    <a onclick="copy(this)" class="copy">${ipObj.networkAddress.toString()}</a>
                </td>
            </tr>
            <tr>
                <td>Broadcast</td>
                <td data-type="address">
                    <a onclick="copy(this)" class="copy">${ipObj.networkAddress.toString()}</a>
                </td>
            </tr>
            <tr>
                <td>Network range</td>
                <td data-type="range">
                    <a onclick="copy(this)" class="copy"><span class="ip-range">${ipObj.networkAddress.toString()}</span> - <span>${ipObj.broadcastAddress.toString()}</span></a>
                </td>
            </tr>
            <tr>
                <td>Hosts Addresses</td>
                <td data-type="range">
                    <a onclick="copy(this)" class="copy"><span class="ip-range">${ipObj.firstAddress.toString()}</span> - <span>${ipObj.lastAddress.toString()}</span></a>
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
                    <button id="checkIpButton" onclick="checkIpInSubnet('${results.network}')">Check</button>
                    <span id="checkResult"></span>
                </td>
            </tr>
        </table>
    `;

    document.getElementById('checkIpInput').addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            checkIpInSubnet(results.network);
        }
    });

    document.getElementById('checkIpButton').addEventListener('click', function() {
        checkIpInSubnet(results.network);
    });

    updateHistory();
    history.store(input);
}

function checkIpInSubnet(network) {
    const ipToCheck = document.getElementById('checkIpInput').value.trim();
    if (!ipToCheck) {
        showCheckResult('Please enter an IP address to check', 'warning');
        return;
    }

    const [networkAddress, prefixLength] = network.split('/');

    try {
        const networkObj = parseIp(network);
        const ipObj = parseIp(ipToCheck);

        if (networkObj.constructor !== ipObj.constructor) {
            throw new Error("IP version mismatch");
        }

        const isInSubnet = ipObj.address >= networkObj.networkAddress && ipObj.address <= networkObj.broadcastAddress;

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

    try {
        displayResults(input.value);

    } catch (error) {
        alert(error.message);
        throw error;
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
    const urlAddress = getAddressFromURL();
    if (urlAddress) { fillForm(urlAddress); } else { fillForm(await history.getLast()); }
    document.getElementById('ipAddress').focus()
}


async function updateHistory() {
    let results = await history.list(50);
    if (results.length === 0) return;
    let historyDiv = document.getElementById('history');
    historyDiv.innerHTML = `
        <h2>History</h2>
        <ul>
            ${results.map(result => `<li><a onclick="fillForm(this.text)">${result.value}</a></li>`).join('')}
        </ul>
    `;
}

document.addEventListener('DOMContentLoaded', main);
