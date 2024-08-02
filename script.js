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
        this.prefixLength = BigInt(prefixLength);
        this.address = this.toInteger(ip);
        this.totalBits = this.getTotalBits();
        this.networkAddress = this.address & this.prefixToMask(this.prefixLength, this.totalBits);
        const broadcastMask = ~this.prefixToMask(this.prefixLength, this.totalBits) & this.prefixToMask(this.totalBits, this.totalBits);
        this.broadcastAddress = this.address | broadcastMask;
        this.firstAddress = this.networkAddress + 1n;
        this.lastAddress = this.broadcastAddress - 1n;
    }

    toInteger(ip) {
        throw new Error("Method 'toInteger(ip)' must be implemented.");
    }

    toString(int) {
        throw new Error("Method 'toString(int)' must be implemented.");
    }

    prefixToMask(prefixLength, totalBits) {
        return (1n << totalBits) - (1n << (totalBits - prefixLength));
    }

    getLength() {
        return 1n << (this.totalBits - this.prefixLength);
    }

    getHexId() {
        return '0x' + this.address.toString(16).padStart(Number(this.totalBits / 4n), '0');
    }

    getArpaFormat() {
        throw new Error("Method 'getArpaFormat()' must be implemented.");
    }

    getType() {
        throw new Error("Method 'getType()' must be implemented.");
    }

    getBase85Id() {
        const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
        let int = this.address;
        let result = '';
        while (int > 0) {
            result = chars[int % 85n] + result;
            int = int / 85n;
        }
        return result;
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

    getTotalBits() {
        return BigInt(32);
    }

    toInteger(ip) {
        return ip.split('.').reduce((int, octet) => int * 256n + BigInt(octet), 0n);
    }

    toString(int) {
        return [
            Number(int >> 24n & 255n),
            Number(int >> 16n & 255n),
            Number(int >> 8n & 255n),
            Number(int & 255n)
        ].join('.');
    }

    getArpaFormat() {
        return this.toString(this.address).split('.').reverse().join('.') + '.in-addr.arpa';
    }

    getType() {
        for (const [type, start, end] of IPv4.TYPE_LIST) {
            if (this.networkAddress >= start && this.broadcastAddress <= end) {
                return type;
            }
        }
        return "Unknown";
    }

    static toBigInt(ip) {
        return ip.split('.').reduce((int, octet) => int * 256n + BigInt(octet), 0n);
    }
}

class IPv6 extends Address {
    static TYPE_LIST = [
        ["Global Unicast", "2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Link-local", "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Unique Local", "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Multicast", "ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        ["Loopback", "::1", "::1"],
        ["Reserved", "::", "::"],
        ["Reserved", "::ffff:0:0", "::ffff:ffff:ffff"],
        ["Reserved", "4000::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
    ].map(([type, start, end]) => [type, IPv6.toBigInt(start), IPv6.toBigInt(end)]);

    getTotalBits() {
        return BigInt(128);
    }

    expandIPv6(ip) {
        const parts = ip.split('::');
        let head = parts[0].split(':').map(part => part || '0');
        let tail = parts[1] ? parts[1].split(':').map(part => part || '0') : [];
        let middle = Array(8 - head.length - tail.length).fill('0');
        return [...head, ...middle, ...tail].join(':');
    }

    toInteger(ip) {
        ip = this.expandIPv6(ip);
        return ip.split(':').reduce((int, hextet) => int * 65536n + BigInt(parseInt(hextet, 16)), 0n);
    }

    toString(int) {
        let hexString = int.toString(16).padStart(32, '0');
        let hextets = [];
        for (let i = 0; i < 32; i += 4) {
            hextets.push(hexString.slice(i, i + 4));
        }
        return hextets.join(':').replace(/(^|:)0{1,3}(?=0+(:|$))/g, '$1').replace(/:{2,}/, '::');
    }

    getArpaFormat() {
        let reversed = this.toString(this.address).split(':').map(part => part.padStart(4, '0')).join('').split('').reverse().join('.');
        return `${reversed}.ip6.arpa`;
    }

    getType() {
        for (const [type, start, end] of IPv6.TYPE_LIST) {
            if (this.networkAddress >= start && this.broadcastAddress <= end) {
                return type;
            }
        }
        return "Unknown";
    }

    static toBigInt(ip) {
        ip = IPv6.prototype.expandIPv6(ip);
        return ip.split(':').reduce((int, hextet) => int * 65536n + BigInt(parseInt(hextet, 16)), 0n);
    }
}

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

function displayResults(results) {
    let resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Address</td><td data-type="address"><a onclick="copy(this)" class="copy">${results.ip}</a></td></tr>
            <tr><td>Type</td><td data-type="type"><a onclick="copy(this)" class="copy">${results.type}</></td></tr>
            <tr><td>Network</td><td data-type="network"><a onclick="copy(this)" class="copy">${results.network}</></td></tr>
            <tr><td>Broadcast</td><td data-type="address"><a onclick="copy(this)" class="copy">${results.broadcast}</></td></tr>
            <tr><td>Network range</td><td data-type="range"><span class="ip-range"><a onclick="copy(this)" class="copy"an>${results.networkRange.split(' - ')[0]}</span> <span>${results.networkRange.split(' - ')[1]}</span></span></a></td></tr>
            <tr><td>Hosts Addresses</td><td data-type="range"><span class="ip-range"><a onclick="copy(this)" class="copy"an>${results.firstAddress}</span> <span>${results.lastAddress}</span></span></a></td></tr>
            <tr><td>Total IP addresses</td><td data-type="number"><a onclick="copy(this)" class="copy">${results.totalAddresses}</></td></tr>
            <tr><td>Integer ID</td><td data-type="id"><a onclick="copy(this)" class="copy">${results.integerId}</></td></tr>
            <tr><td>Hexadecimal ID</td><td data-type="id"><a onclick="copy(this)" class="copy">${results.hexId}</></td></tr>
            <tr><td>Dotted decimal ID</td><td data-type="address"><a onclick="copy(this)" class="copy">${results.dottedDecimalId}</></td></tr>
            <tr><td>Base 85 ID</td><td data-type="id"><a onclick="copy(this)" class="copy">${results.base85Id}</></td></tr>
            <tr><td>arpa Format</td><td data-type="address"><a onclick="copy(this)" class="copy">${results.arpaFormat}</></td></tr>
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

function analyzeIp(input) {
    let ipObj = parseIp(input);
    setAddressInURL(input);
    return {
        ip: `${ipObj.toString(ipObj.address)}/${Number(ipObj.prefixLength)}`,
        type: ipObj.getType(),
        network: `${ipObj.toString(ipObj.networkAddress)}/${Number(ipObj.prefixLength)}`,
        broadcast: ipObj.toString(ipObj.broadcastAddress),
        networkRange: `${ipObj.toString(ipObj.networkAddress)} - ${ipObj.toString(ipObj.broadcastAddress)}`,
        firstAddress: ipObj.toString(ipObj.firstAddress),
        lastAddress: ipObj.toString(ipObj.lastAddress),
        totalAddresses: ipObj.getLength().toString(),
        integerId: ipObj.address.toString(),
        hexId: ipObj.getHexId(),
        dottedDecimalId: ipObj.toString(ipObj.address),
        base85Id: ipObj.getBase85Id(),
        arpaFormat: ipObj.getArpaFormat()
    };
}

document.getElementById('ipForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const input = document.getElementById('ipAddress');

    try {
        let results = analyzeIp(input.value);
        displayResults(results);
        history.store(input.value);
    } catch (error) {
        alert(error.message);
    }
});

const history = new History();

function fillForm(value) {
    value = value || this.value;
    if (!value) return;

    document.getElementById('ipAddress').value = value;
    let results = analyzeIp(value);
    displayResults(results);
    updateHistory();
}

async function main() {
    await history.init();

    const urlAddress = getAddressFromURL();
    if (urlAddress) {
        document.getElementById('ipAddress').value = urlAddress;
        document.getElementById('ipForm').dispatchEvent(new Event('submit'));
        updateHistory();
    } else {
        let result = await history.getLast();
        if (result && result.value) { fillForm(result.value); }
    }

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
