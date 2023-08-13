const { createGzip } = require('node:zlib');
const { pipeline, Readable } = require('node:stream');
const {
  createWriteStream,
  readFileSync,
  writeFileSync
} = require('node:fs');
const {dirname, join, basename}= require('node:path');
const process= require('node:process');
const {minify} = require('html-minifier');

if( process.argv.length < 4 ) {
	console.error('Error: Missing file paths');
	process.exit(-1)
}

const htmlFilePath= process.argv[2];
const outputPath= process.argv[3];
console.log(`Building '${htmlFilePath}'...`);

const basePath= dirname(htmlFilePath);

const templateString= readFileSync(htmlFilePath, 'utf8');
const assembledString= templateString.replaceAll(/{{> ([^}]+)}}/g, (match, fileName) => {
	const filePath= join(basePath, fileName);
	console.log(`Inserting file '${filePath}'`);
	return readFileSync(filePath, 'utf8');
});

console.log('Minifying...');

const minifiedString= minify(assembledString, {
  caseSensitive: true,
  collapseBooleanAttributes: true,
  collapseInlineTagWhitespace: true,
  collapseWhitespace: true,
  minifyCSS: true,
  minifyJS: true,
  removeComments: true,
  removeEmptyAttributes: true,
  removeRedundantAttributes: true,
  useShortDoctype: true
});


const tempPath= htmlFilePath+ '.gz';

const gzip = createGzip();
const sourceStream = new Readable();
const destinationStream = createWriteStream(tempPath);

sourceStream.push(minifiedString);
sourceStream.push(null);

pipeline(sourceStream, gzip, destinationStream, (err) => {
  if (err) {
    console.error('An error occurred when compressing:', err);
    process.exit(-1);
    return;
  }
  
  let str= 'u8 compressedHtml[] PROGMEM = {\n';
  const buffer= readFileSync(tempPath);
  for(let i= 0; i!== buffer.length; i++) {
    str+= '0x'+ buffer[i].toString(16);
	
    if( i!== buffer.length-1 ) {
      str+= ',';
    }
    
    if( (i+1) % 16 === 0 ) {
      str+= '\n';
    }
  }
  
  str+= '};\n';
  
  const outFileName= join(outputPath, basename(htmlFilePath)+ '.inl.h');
  console.log(`Writing '${outFileName}' file (array size ${buffer.length} bytes)...`);
  writeFileSync(outFileName, str, 'utf-8');
});

