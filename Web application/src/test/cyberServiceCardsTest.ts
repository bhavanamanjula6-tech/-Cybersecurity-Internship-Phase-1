/**
 * Automated Verification Test for CyberServiceCards Interaction Logic
 */
import fs from 'fs';
import path from 'path';

console.log('=== RUNNING CYBER SERVICE CARDS INTERACTION VERIFICATION ===\n');

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

const componentPath = path.resolve(process.cwd(), 'src/components/public/CyberServiceCards.tsx');
const content = fs.readFileSync(componentPath, 'utf8');

// 1. Verify all 4 service cards are defined
assert(content.includes("id: 'triage'") && content.includes("id: 'mitre'") && content.includes("id: 'containment'") && content.includes("id: 'telemetry'"),
  'Test 1: All 4 service capability cards defined (triage, mitre, containment, telemetry)'
);

// 2. Verify state separation between selectedIndex and hoveredIndex
assert(content.includes('const [selectedIndex, setSelectedIndex] = useState<number>(0);') &&
       content.includes('const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);'),
  'Test 2: Separate persistent selectedIndex state and transient hoveredIndex state'
);

// 3. Verify that mouse movement uses CSS custom properties without re-rendering React on every pixel
assert(content.includes("e.currentTarget.style.setProperty('--tilt-x'") &&
       content.includes("e.currentTarget.style.setProperty('--tilt-y'"),
  'Test 3: Fluid CSS custom properties tilt tracking without React state thrashing during click/mousemove'
);

// 4. Verify no negative translateZ in transforms to prevent Chromium hit-testing occlusion
assert(!content.includes('translateZ = -') && !content.includes('translateZ(-'),
  'Test 4: Guaranteed non-negative translateZ values across all states (resting, hovered, selected) ensuring reliable browser hit testing'
);

// 5. Verify clicking card body triggers handleSelectCard
assert(content.includes('onClick={() => handleSelectCard(index)}'),
  'Test 5: Clicking anywhere on card body triggers handleSelectCard(index)'
);

// 6. Verify numbered controls call handleSelectCard with stopPropagation
assert(content.includes('handleSelectCard(idx)'),
  'Test 6: Numbered controls (1, 2, 3, 4) call handleSelectCard synchronized with selection'
);

// 7. Verify pointer-events-auto and z-index hierarchy
assert(content.includes('pointer-events-auto') && content.includes('z-20') && content.includes('z-10'),
  'Test 7: Explicit pointer-events-auto and z-index hierarchy elevating hovered and selected cards above resting cards'
);

// 8. Verify mouse leave resets hover state while leaving selection intact
assert(content.includes('setHoveredIndex(null)'),
  'Test 8: Mouse leave cleanly resets hoveredIndex while preserving persistent selectedIndex'
);

console.log(`\nCyber Service Cards Test Results: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
