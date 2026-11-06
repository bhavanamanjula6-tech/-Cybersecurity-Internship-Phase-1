import React from 'react';
import { motion, useReducedMotion } from 'motion/react';

interface CyberLockIllustrationProps {
  className?: string;
}

export const CyberLockIllustration: React.FC<CyberLockIllustrationProps> = ({ className = '' }) => {
  const shouldReduceMotion = useReducedMotion();

  return (
    <div
      className={`relative flex items-center justify-center select-none ${className}`}
      aria-label="Deterministic Security Governance and Biometric Lock Illustration"
      role="img"
    >
      {/* Ambient Radial Mesh Behind Lock */}
      <div
        className="absolute inset-0 pointer-events-none rounded-full blur-2xl opacity-45 dark:opacity-60"
        style={{
          background: 'radial-gradient(circle, rgba(124,58,237,0.3) 0%, rgba(6,182,212,0.15) 50%, transparent 75%)',
        }}
      />

      {/* SVG Digital Lock & Biometric Fingerprint Assembly */}
      <svg
        viewBox="0 0 260 280"
        className="relative z-10 w-full max-w-64 sm:max-w-72 filter drop-shadow-[0_12px_24px_rgba(10,14,35,0.4)]"
      >
        <defs>
          <linearGradient id="lockShackleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#8b5cf6" />
            <stop offset="50%" stopColor="#d946ef" />
            <stop offset="100%" stopColor="#06b6d4" />
          </linearGradient>

          <linearGradient id="lockBodyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#111633" />
            <stop offset="60%" stopColor="#0d1124" />
            <stop offset="100%" stopColor="#080c1b" />
          </linearGradient>

          <linearGradient id="fingerprintGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="50%" stopColor="#a855f7" />
            <stop offset="100%" stopColor="#e879f9" />
          </linearGradient>
        </defs>

        {/* Shackle: Curved Arch with Stepped Shoulders */}
        <path
          d="M75 120 L75 75 C75 42 98 20 130 20 C162 20 185 42 185 75 L185 120"
          fill="none"
          stroke="url(#lockShackleGrad)"
          strokeWidth="12"
          strokeLinecap="round"
        />

        {/* Shackle Accent Inset Stripe */}
        <path
          d="M85 110 L85 75 C85 50 105 32 130 32 C155 32 175 50 175 75 L175 110"
          fill="none"
          stroke="#060914"
          strokeWidth="3"
        />

        {/* Main Padlock Body */}
        <rect
          x="45"
          y="105"
          width="170"
          height="150"
          rx="24"
          fill="url(#lockBodyGrad)"
          stroke="url(#lockShackleGrad)"
          strokeWidth="3"
        />

        {/* Inner Beveled Perimeter */}
        <rect
          x="55"
          y="115"
          width="150"
          height="130"
          rx="18"
          fill="none"
          stroke="rgba(139,92,246,0.3)"
          strokeWidth="1.5"
          strokeDasharray="8 4"
        />

        {/* Biometric Fingerprint Ridges */}
        <g stroke="url(#fingerprintGrad)" strokeWidth="2.5" fill="none" strokeLinecap="round" opacity="0.9">
          {/* Innermost loop */}
          <path d="M125 180 C125 174 135 174 135 180 C135 188 126 195 130 203" />
          {/* Second ridge */}
          <path d="M118 180 C118 168 142 168 142 180 C142 194 122 202 125 214" />
          {/* Third ridge */}
          <path d="M111 180 C111 161 149 161 149 180 C149 200 118 209 121 222" />
          {/* Fourth ridge */}
          <path d="M104 182 C104 154 156 154 156 182 C156 208 114 216 117 230" />
          {/* Outer ridge */}
          <path d="M97 185 C97 148 163 148 163 185 C163 214 110 224 112 236" />
        </g>

        {/* Circuit Interconnects Radiating from Lock */}
        <g stroke="#8b5cf6" strokeWidth="1.5" fill="none" opacity="0.75">
          <path d="M45 140 L25 140 L15 150" />
          <path d="M45 200 L20 200 L10 190" />
          <path d="M215 140 L235 140 L245 150" />
          <path d="M215 200 L240 200 L250 190" />
        </g>

        {/* Active Circuit Terminus Nodes */}
        <circle cx="15" cy="150" r="3.5" fill="#22d3ee" className={shouldReduceMotion ? '' : 'animate-pulse'} />
        <circle cx="10" cy="190" r="3" fill="#e879f9" />
        <circle cx="245" cy="150" r="3.5" fill="#a855f7" className={shouldReduceMotion ? '' : 'animate-pulse'} />
        <circle cx="250" cy="190" r="3" fill="#22d3ee" />

        {/* Central Keyway Glow Indicator */}
        <circle cx="130" cy="140" r="6" fill="#a855f7" />
        <circle cx="130" cy="140" r="3" fill="#ffffff" />
      </svg>
    </div>
  );
};
