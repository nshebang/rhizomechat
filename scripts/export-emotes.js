import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const emotesDir = path.join(__dirname, '..', 'public', 'img', 'emotes');
const configFilePath = path.join(__dirname, '..', 'config.json');

if (!fs.existsSync(configFilePath)) {
  console.error('Error: opening config.json (no such file or directory)');
  process.exit(1);
}

try {
  const configFile = fs.readFileSync('config.json', 'utf8');
  const config = JSON.parse(configFile);
  
  const existingEmotes = config.emotes || {};
  const newEmotes = {};
  
  const files = fs.readdirSync(emotesDir);
  
  files.forEach(file => {
    if (file.match(/\.(png|jpg|jpeg|gif)$/i)) {
      const emoteName = path.parse(file).name;
      newEmotes[emoteName] = file;
    }
  });
  
  const mergedEmotes = { ...existingEmotes, ...newEmotes };
  
  const updatedConfig = {
    ...config,
    emotes: mergedEmotes
  };
  
  fs.writeFileSync('config.json', JSON.stringify(updatedConfig, null, 2));
  
  console.log('New emotes successfully added to config file.');
} catch (err) {
  console.error('Error: unable to export emotes: ', err);
  process.exit(1);
}
