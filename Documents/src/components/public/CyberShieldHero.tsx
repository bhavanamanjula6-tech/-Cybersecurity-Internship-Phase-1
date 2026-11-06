import React, { useState, useRef, useEffect } from 'react';
import { motion, useReducedMotion } from 'motion/react';

interface CyberShieldHeroProps {
  className?: string;
}

export const CyberShieldHero: React.FC<CyberShieldHeroProps> = ({ className = '' }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const shouldReduceMotion = useReducedMotion();

  // Pointer tilt state: [-1, 1] range
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);
  const [isTouchDevice, setIsTouchDevice] = useState(false);

  useEffect(() => {
    setIsTouchDevice('ontouchstart' in window || navigator.maxTouchPoints > 0);
  }, []);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (shouldReduceMotion || isTouchDevice || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    // Normalized [-1, 1] offset
    const normX = (e.clientX - centerX) / (rect.width / 2);
    const normY = (e.clientY - centerY) / (rect.height / 2);
    setTilt({
      x: Math.max(-1, Math.min(1, normX)),
      y: Math.max(-1, Math.min(1, normY)),
    });
  };

  const handleMouseEnter = () => {
    if (!shouldReduceMotion && !isTouchDevice) setIsHovered(true);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    setTilt({ x: 0, y: 0 });
  };

  // Tilt angles: pointer X creates rotateY, pointer Y creates rotateX (inverted)
  const rotateX = shouldReduceMotion ? 0 : -tilt.y * 8;
  const rotateY = shouldReduceMotion ? 0 : tilt.x * 8;

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className={`relative w-72 h-72 sm:w-88 sm:h-88 md:w-96 md:h-96 flex items-center justify-center select-none perspective-1000 ${className}`}
      aria-label="Layered 2.5D Animated CyberShield"
      role="img"
    >
      {/* 1. Ambient Background Glow Field */}
      {/* Light Theme Glow (preserved untouched) */}
      <div
        className="absolute inset-0 pointer-events-none rounded-full blur-3xl opacity-60 dark:hidden transition-opacity duration-700"
        style={{
          background: 'radial-gradient(circle, rgba(168,85,247,0.3) 0%, rgba(217,70,239,0.18) 35%, rgba(6,182,212,0.12) 65%, transparent 80%)',
        }}
      />

      {/* Dark Theme: Smooth, Diffuse Violet-Magenta Cinematic Halo */}
      {/* Outer diffuse halo concentrated behind the shield with gentle falloff fading seamlessly into deep navy background (#060814) */}
      <div
        className="absolute -inset-5 sm:-inset-7 md:-inset-9 pointer-events-none rounded-full blur-3xl hidden dark:block transition-opacity duration-700"
        style={{
          background:
            'radial-gradient(circle at 50% 48%, rgba(168,85,247,0.09) 0%, rgba(217,70,239,0.04) 24%, rgba(147,51,234,0.015) 45%, transparent 65%)',
        }}
      />
      {/* Inner focused violet luminescence tightly supporting the shield silhouette without broad wash */}
      <div
        className="absolute inset-4 sm:inset-2 md:inset-0 pointer-events-none rounded-full blur-2xl hidden dark:block transition-opacity duration-700 opacity-45"
        style={{
          background:
            'radial-gradient(ellipse at 50% 46%, rgba(192,38,211,0.08) 0%, rgba(147,51,234,0.03) 28%, transparent 54%)',
        }}
      />

      {/* 2. Concentric Orbital Ground Rings (3D Perspective tilted plane) */}
      <div
        className="absolute bottom-2 sm:bottom-4 w-[115%] h-36 pointer-events-none flex items-center justify-center"
        style={{
          transform: 'rotateX(68deg) translateZ(-40px)',
          transformStyle: 'preserve-3d',
        }}
      >
        {/* Outer Ring */}
        <motion.div
          animate={shouldReduceMotion ? {} : { rotate: 360 }}
          transition={{ duration: 42, repeat: Infinity, ease: 'linear' }}
          className="absolute w-72 h-72 sm:w-84 sm:h-84 md:w-96 md:h-96 rounded-full border border-dashed border-purple-500/40 dark:border-purple-400/50 shadow-[0_0_15px_rgba(168,85,247,0.25)]"
        />

        {/* Mid Pulsing Accent Ring */}
        <motion.div
          animate={shouldReduceMotion ? {} : { rotate: -360 }}
          transition={{ duration: 28, repeat: Infinity, ease: 'linear' }}
          className="absolute w-56 h-56 sm:w-64 sm:h-64 md:w-72 md:h-72 rounded-full border border-cyan-400/40 dark:border-cyan-300/50 shadow-[0_0_20px_rgba(6,182,212,0.3)]"
        />

        {/* Inner Luminous Ring */}
        <motion.div
          animate={shouldReduceMotion ? {} : { scale: [0.97, 1.03, 0.97], opacity: [0.6, 0.9, 0.6] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
          className="absolute w-40 h-40 sm:w-48 sm:h-48 rounded-full border-2 border-magenta-500/50 dark:border-fuchsia-400/60 shadow-[0_0_25px_rgba(217,70,239,0.45)]"
        />

        {/* Orbiting Photon Nodes */}
        {!shouldReduceMotion && (
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 14, repeat: Infinity, ease: 'linear' }}
            className="absolute w-64 h-64 sm:w-76 sm:h-76 pointer-events-none"
          >
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-cyan-300 shadow-[0_0_8px_#22d3ee]" />
            <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-2.5 h-2.5 rounded-full bg-fuchsia-400 shadow-[0_0_10px_#e879f9]" />
          </motion.div>
        )}
      </div>

      {/* 3. Main Multi-Plane 2.5D Shield Assembly */}
      <motion.div
        animate={
          shouldReduceMotion
            ? {}
            : {
                y: isHovered ? [-2, 2, -2] : [-7, 7, -7],
              }
        }
        transition={{
          duration: 4.8,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
        style={{
          transform: `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`,
          transformStyle: 'preserve-3d',
          transition: isHovered ? 'transform 0.12s ease-out' : 'transform 0.6s ease-out',
        }}
        className="relative z-10 w-52 h-64 sm:w-60 sm:h-74 md:w-68 md:h-84 flex items-center justify-center transform-style-3d cursor-pointer"
      >
        {/* Layer A (Back Depth Extrusion): Shadow & Bevel Cast */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ transform: 'translateZ(-16px)', transformStyle: 'preserve-3d' }}
        >
          <svg viewBox="0 0 240 290" className="w-full h-full filter drop-shadow-[0_20px_35px_rgba(10,14,35,0.7)]">
            <path
              d="M120 10 L215 48 L215 145 C215 210 175 258 120 280 C65 258 25 210 25 145 L25 48 Z"
              fill="#060914"
              stroke="rgba(139,92,246,0.3)"
              strokeWidth="3"
            />
          </svg>
        </div>

        {/* Layer B (Mid Base Shield Body): Metallic & Dark Cyber Gradient with Controlled Edge Lighting */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ transform: 'translateZ(0px)', transformStyle: 'preserve-3d' }}
        >
          <svg viewBox="0 0 240 290" className="w-full h-full overflow-visible">
            <defs>
              {/* Dark Obsidian-Indigo Shield Body Gradient */}
              <linearGradient id="shieldBodyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#0a0c1b" />
                <stop offset="50%" stopColor="#060814" />
                <stop offset="100%" stopColor="#03040c" />
              </linearGradient>

              {/* Controlled Violet-to-Magenta Rim Gradient with Electric Cyan Apex */}
              <linearGradient id="shieldRimGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#a855f7" />
                <stop offset="35%" stopColor="#d946ef" />
                <stop offset="65%" stopColor="#c026d3" />
                <stop offset="85%" stopColor="#06b6d4" />
                <stop offset="100%" stopColor="#22d3ee" />
              </linearGradient>

              {/* Shield Edge Bloom Filter for Direct Silhouette Illumination */}
              <filter id="shieldRimBloom" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur1" />
                <feGaussianBlur stdDeviation="6" result="blur2" />
                <feMerge>
                  <feMergeNode in="blur2" />
                  <feMergeNode in="blur1" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              {/* Upper Crest Highlight */}
              <linearGradient id="crestHighlightGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#f0abfc" stopOpacity="0.85" />
                <stop offset="40%" stopColor="#d946ef" stopOpacity="0.6" />
                <stop offset="100%" stopColor="#a855f7" stopOpacity="0.2" />
              </linearGradient>

              {/* Deeper Indigo-Navy Inset Chamber (Dark upper interior with subtle violet holographic tint) */}
              <linearGradient id="innerGlowGrad" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%" stopColor="#090b1c" />
                <stop offset="35%" stopColor="#0c0e25" />
                <stop offset="68%" stopColor="#070918" />
                <stop offset="100%" stopColor="#03050f" />
              </linearGradient>
            </defs>

            {/* Edge Bloom: Direct Silhouette Illumination */}
            <path
              d="M120 12 L212 49 L212 143 C212 206 173 253 120 275 C67 253 28 206 28 143 L28 49 Z"
              fill="none"
              stroke="url(#shieldRimGrad)"
              strokeWidth="5"
              filter="url(#shieldRimBloom)"
              className="opacity-40 dark:opacity-65"
            />

            {/* Base Shield Polygon Body */}
            <path
              d="M120 12 L212 49 L212 143 C212 206 173 253 120 275 C67 253 28 206 28 143 L28 49 Z"
              fill="url(#shieldBodyGrad)"
              stroke="url(#shieldRimGrad)"
              strokeWidth="3"
            />

            {/* Upper Crest Facet Edge Lighting */}
            <path
              d="M120 12 L212 49 L212 143"
              fill="none"
              stroke="url(#crestHighlightGrad)"
              strokeWidth="1.5"
              strokeLinecap="round"
              className="opacity-70 dark:opacity-90"
            />
            <path
              d="M120 12 L28 49 L28 143"
              fill="none"
              stroke="url(#crestHighlightGrad)"
              strokeWidth="1.5"
              strokeLinecap="round"
              className="opacity-70 dark:opacity-90"
            />

            {/* Lower Rim Cyan Accent Highlight */}
            <path
              d="M212 143 C212 206 173 253 120 275 C67 253 28 206 28 143"
              fill="none"
              stroke="#06b6d4"
              strokeWidth="2.5"
              strokeLinecap="round"
              className="opacity-80 dark:opacity-95"
            />

            {/* Inner Inset Chamber */}
            <path
              d="M120 28 L196 58 L196 138 C196 190 162 232 120 252 C78 232 44 190 44 138 L44 58 Z"
              fill="url(#innerGlowGrad)"
              stroke="rgba(168,85,247,0.2)"
              strokeWidth="1.25"
              strokeDasharray="6 3"
            />
          </svg>
        </div>

        {/* Layer C (Circuits & Cyber Architecture): SVG Traces with Nodes */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ transform: 'translateZ(14px)', transformStyle: 'preserve-3d' }}
        >
          <svg viewBox="0 0 240 290" className="w-full h-full">
            <g stroke="#a855f7" strokeWidth="1.75" fill="none" opacity="0.9">
              {/* Top Left Circuit Bus */}
              <path d="M60 70 L95 70 L110 85 L110 110" />
              {/* Top Right Circuit Bus */}
              <path d="M180 70 L145 70 L130 85 L130 110" />
              {/* Bottom Traces */}
              <path d="M80 175 L105 200 L120 200 L135 200 L160 175" />
              <path d="M120 200 L120 240" stroke="#06b6d4" strokeWidth="2" />
            </g>

            {/* Circuit Nodes with Pulsing Glow */}
            <circle cx="60" cy="70" r="3" fill="#22d3ee" className="animate-pulse" />
            <circle cx="180" cy="70" r="3" fill="#e879f9" className="animate-pulse" />
            <circle cx="80" cy="175" r="2.5" fill="#a855f7" />
            <circle cx="160" cy="175" r="2.5" fill="#a855f7" />
            <circle cx="120" cy="240" r="3" fill="#22d3ee" className="animate-pulse" />
          </svg>
        </div>

        {/* Layer D (Elevated Core / Cybernetic Engine): Floating Center Emblem */}
        <div
          className="absolute pointer-events-none flex items-center justify-center"
          style={{ transform: 'translateZ(26px)', transformStyle: 'preserve-3d' }}
        >
          {/* Subtle Central Illumination concentrated around the Lock & Processor motif */}
          <div
            className="absolute w-20 h-20 rounded-full blur-md pointer-events-none"
            style={{
              background:
                'radial-gradient(circle, rgba(217,70,239,0.18) 0%, rgba(147,51,234,0.08) 45%, transparent 68%)',
            }}
          />

          {/* Core Hexagonal Chassis */}
          <svg viewBox="0 0 100 100" className="w-20 h-20 sm:w-24 sm:h-24">
            <defs>
              <linearGradient id="coreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#7c3aed" />
                <stop offset="50%" stopColor="#c026d3" />
                <stop offset="100%" stopColor="#0891b2" />
              </linearGradient>
            </defs>

            {/* Outer Hexagon */}
            <polygon
              points="50,10 85,28 85,72 50,90 15,72 15,28"
              fill="#090d20"
              stroke="url(#coreGrad)"
              strokeWidth="2.5"
            />

            {/* Inner Hexagon Core */}
            <polygon
              points="50,22 75,36 75,64 50,78 25,64 25,36"
              fill="rgba(139,92,246,0.2)"
              stroke="#22d3ee"
              strokeWidth="1.5"
            />

            {/* Central Microprocessor / Lock Icon Graphic */}
            <path
              d="M44 42 L56 42 L56 40 C56 36.7 53.3 34 50 34 C46.7 34 44 36.7 44 40 Z"
              stroke="#e879f9"
              strokeWidth="2"
              fill="none"
            />
            <rect
              x="42"
              y="42"
              width="16"
              height="14"
              rx="2"
              fill="#8b5cf6"
              stroke="#22d3ee"
              strokeWidth="1.5"
            />
            <circle cx="50" cy="49" r="2" fill="#ffffff" />
          </svg>
        </div>

        {/* Layer E (Shaped Silhouette Reflection): Subtle Violet-to-Magenta Specular Sheen */}
        {/* Strictly clipped to the exact shield silhouette SVG path to eliminate escaping light or rectangular streaks */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ transform: 'translateZ(30px)', transformStyle: 'preserve-3d' }}
        >
          <svg viewBox="0 0 240 290" className="w-full h-full overflow-hidden">
            <defs>
              {/* Exact shield silhouette clipPath */}
              <clipPath id="shieldSheenSilhouetteClip">
                <path d="M120 12 L212 49 L212 143 C212 206 173 253 120 275 C67 253 28 206 28 143 L28 49 Z" />
              </clipPath>

              {/* Violet-to-Magenta reflective sheen gradient */}
              <linearGradient id="sheenBeamGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="rgba(168,85,247,0)" />
                <stop offset="28%" stopColor="rgba(168,85,247,0.05)" />
                <stop offset="42%" stopColor="rgba(217,70,239,0.18)" />
                <stop offset="50%" stopColor="rgba(244,114,182,0.28)" />
                <stop offset="56%" stopColor="rgba(192,38,211,0.2)" />
                <stop offset="70%" stopColor="rgba(147,51,234,0.07)" />
                <stop offset="100%" stopColor="rgba(6,182,212,0)" />
              </linearGradient>

              {/* Upper facet glass curvature highlight */}
              <linearGradient id="upperFacetGrad" x1="50%" y1="0%" x2="50%" y2="100%">
                <stop offset="0%" stopColor="rgba(217,70,239,0.08)" />
                <stop offset="55%" stopColor="rgba(168,85,247,0.02)" />
                <stop offset="100%" stopColor="transparent" />
              </linearGradient>
            </defs>

            {/* Clipped exclusively inside the shield silhouette */}
            <g clipPath="url(#shieldSheenSilhouetteClip)">
              {/* Dynamic pointer-responsive sheen band */}
              <g
                style={{
                  transform: `translate(${tilt.x * 24}px, ${tilt.y * 20}px)`,
                  transition: isHovered ? 'transform 0.12s ease-out' : 'transform 0.6s ease-out',
                }}
              >
                {/* Diagonal specular sheen angled across the shield */}
                <rect
                  x="-60"
                  y="-40"
                  width="360"
                  height="360"
                  fill="url(#sheenBeamGrad)"
                  transform="rotate(-28 120 145)"
                  style={{ mixBlendMode: 'screen' }}
                />
              </g>

              {/* Subtle upper facet specular reflection */}
              <path
                d="M120 16 L206 50 L206 115 C175 92 145 84 120 84 C95 84 65 92 34 115 L34 50 Z"
                fill="url(#upperFacetGrad)"
                opacity="0.4"
                style={{ mixBlendMode: 'screen' }}
              />
            </g>
          </svg>
        </div>
      </motion.div>
    </div>
  );
};
