const fs = require('fs');
const path = require('path');

// Copy _next directory to static directory for GitHub Pages compatibility
function copyNextAssets() {
  const outDir = path.join(__dirname, 'out');
  const nextDir = path.join(outDir, '_next');
  const staticDir = path.join(outDir, 'static');
  
  if (fs.existsSync(nextDir)) {
    // Create static directory
    if (!fs.existsSync(staticDir)) {
      fs.mkdirSync(staticDir, { recursive: true });
    }
    
    // Copy _next contents to static
    copyDir(nextDir, staticDir);
    
    console.log('✅ Copied _next assets to static directory for GitHub Pages compatibility');
  }
}

function copyDir(src, dest) {
  const entries = fs.readdirSync(src, { withFileTypes: true });
  
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    
    if (entry.isDirectory()) {
      if (!fs.existsSync(destPath)) {
        fs.mkdirSync(destPath, { recursive: true });
      }
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

copyNextAssets();
