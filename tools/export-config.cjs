'use strict';
// Use only with YOUR trusted configuration: require() executes JavaScript.
const path = require('path');
const fs = require('fs');
const input = process.argv[2];
if (!input) {
  console.error('Usage: node tools/export-config.cjs /path/to/config.js > legacy.json');
  process.exit(1);
}
const config = require(path.resolve(input));
function loadRooms(root) {
  const devices = [];
  for (const item of fs.readdirSync(root, {withFileTypes: true}).sort((a,b) => a.name.localeCompare(b.name))) {
    if (!item.isDirectory()) continue;
    const dir = path.join(root, item.name);
    const roomInfo = {name: item.name, id: item.name};
    for (const file of fs.readdirSync(dir).sort()) {
      // Do not require a room index: the original OR condition re-requires itself.
      if (file === 'index.js' || path.extname(file) !== '.js' || !fs.statSync(path.join(dir,file)).isFile()) continue;
      const create = require(path.join(dir, file));
      if (typeof create !== 'function') throw new Error(`Expected device factory in ${file}`);
      devices.push(create(roomInfo));
    }
  }
  return devices;
}
// config.js may already import devices/rooms. This is optional when devices
// are absent from config, and does not guess a path.
if (process.argv[3]) config.devices = loadRooms(path.resolve(process.argv[3]));
process.stdout.write(JSON.stringify(config, null, 2) + '\n');
