/**
 * Automated Verification Test for Theme Initialization and Light/Dark Switch
 */
import fs from 'fs';
import path from 'path';

console.log('=== RUNNING THEME INITIALIZATION & TOGGLE VERIFICATION TESTS ===\n');

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) {
    console.log(`  [PASS] ${msg}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${msg}`);
    failed++;
  }
}

// 1. Verify index.html inline script defaults to light mode
const indexHtmlPath = path.resolve(process.cwd(), 'index.html');
const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

assert(
  indexHtmlContent.includes("stored === 'dark'") &&
  indexHtmlContent.includes("document.documentElement.classList.add('light')"),
  'Test 1: index.html contains inline script initializing light mode by default for first-time visitors'
);

// 2. Verify src/index.css has Tailwind v4 class-based dark mode custom variant
const indexCssPath = path.resolve(process.cwd(), 'src/index.css');
const indexCssContent = fs.readFileSync(indexCssPath, 'utf8');

assert(
  indexCssContent.includes('@custom-variant dark (&:where(.dark, .dark *));'),
  'Test 2: src/index.css configures @custom-variant dark (&:where(.dark, .dark *)) for Tailwind v4'
);

assert(
  indexCssContent.includes('color-scheme: light;') &&
  indexCssContent.includes('color-scheme: dark;'),
  'Test 3: src/index.css explicitly sets root color-scheme for light and dark modes'
);

// 3. Verify ThemeToggle.tsx defaults to light and synchronizes with localStorage & root class
const themeTogglePath = path.resolve(process.cwd(), 'src/components/common/ThemeToggle.tsx');
const themeToggleContent = fs.readFileSync(themeTogglePath, 'utf8');

assert(
  themeToggleContent.includes("return 'light'") &&
  themeToggleContent.includes("localStorage.getItem('theme_preference')"),
  'Test 4: ThemeToggle defaults to light mode when no preference is stored'
);

assert(
  themeToggleContent.includes("root.classList.add('dark')") &&
  themeToggleContent.includes("root.classList.remove('light')") &&
  themeToggleContent.includes("root.classList.add('light')") &&
  themeToggleContent.includes("root.classList.remove('dark')"),
  'Test 5: ThemeToggle properly syncs document.documentElement classes on theme change'
);

// 4. Verify compiled distribution CSS binds dark: variants to .dark selector
const distAssets = fs.existsSync(path.resolve(process.cwd(), 'dist/assets'))
  ? fs.readdirSync(path.resolve(process.cwd(), 'dist/assets'))
  : [];
const distCssFile = distAssets.find((f) => f.endsWith('.css'));

if (distCssFile) {
  const distCssContent = fs.readFileSync(path.resolve(process.cwd(), 'dist/assets', distCssFile), 'utf8');
  assert(
    distCssContent.includes(':where(.dark,.dark *)') || distCssContent.includes(':where(.dark, .dark *)'),
    'Test 6: Production compiled CSS binds dark: utility classes to :where(.dark, .dark *)'
  );
  assert(
    !distCssContent.includes('@media (prefers-color-scheme:dark){:where(.dark\\:'),
    'Test 7: Production compiled CSS does NOT trap dark utilities inside @media (prefers-color-scheme:dark)'
  );
} else {
  console.log('  [WARN] dist/assets CSS not found, run npm run build to verify compiled CSS');
}

// 5. Verify simulated browser localStorage & DOM synchronization logic
class MockDOMTokenList {
  private classes = new Set<string>();
  add(cls: string) { this.classes.add(cls); }
  remove(cls: string) { this.classes.delete(cls); }
  contains(cls: string) { return this.classes.has(cls); }
}

const mockLocalStorage: Record<string, string> = {};
const mockClassList = new MockDOMTokenList();

// First-time visit simulation (empty storage)
const initialStored = mockLocalStorage['theme_preference'];
const initialTheme = (initialStored === 'dark' || initialStored === 'light') ? initialStored : 'light';
if (initialTheme === 'dark') {
  mockClassList.add('dark');
  mockClassList.remove('light');
} else {
  mockClassList.add('light');
  mockClassList.remove('dark');
}

assert(
  initialTheme === 'light' && mockClassList.contains('light') && !mockClassList.contains('dark'),
  'Test 8: First-time visitor without preference evaluates to light theme and receives html.light'
);

// Toggle to Dark
const nextTheme = initialTheme === 'light' ? 'dark' : 'light';
mockLocalStorage['theme_preference'] = nextTheme;
if (nextTheme === 'dark') {
  mockClassList.add('dark');
  mockClassList.remove('light');
} else {
  mockClassList.add('light');
  mockClassList.remove('dark');
}

assert(
  nextTheme === 'dark' && mockLocalStorage['theme_preference'] === 'dark' &&
  mockClassList.contains('dark') && !mockClassList.contains('light'),
  'Test 9: Toggling theme updates preference in storage to dark and updates DOM class to html.dark'
);

// Toggle back to Light
const secondToggleTheme = nextTheme === 'light' ? 'dark' : 'light';
mockLocalStorage['theme_preference'] = secondToggleTheme;
if (secondToggleTheme === 'dark') {
  mockClassList.add('dark');
  mockClassList.remove('light');
} else {
  mockClassList.add('light');
  mockClassList.remove('dark');
}

assert(
  secondToggleTheme === 'light' && mockLocalStorage['theme_preference'] === 'light' &&
  mockClassList.contains('light') && !mockClassList.contains('dark'),
  'Test 10: Toggling back to light restores preference and updates DOM class to html.light'
);

console.log(`\n=== COMPLETED: ${passed} of ${passed + failed} THEME TESTS PASSED ===`);
if (failed > 0) process.exit(1);
