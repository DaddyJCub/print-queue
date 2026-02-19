/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/templates/**/*.html",
    "./app/static/**/*.js",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["IBM Plex Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // Printellect device sub-brand accent (intentionally teal)
        device: {
          accent: "#3ad5a8",
          panel: "#13232d",
          bg: "#0c181e",
        },
      },
      animation: {
        shimmer: "shimmer 1.5s infinite",
        fadeIn: "fadeIn 0.2s ease-out",
        staggerIn: "staggerIn 0.3s ease-out forwards",
        "bounce-subtle": "bounce-subtle 2s infinite",
      },
      keyframes: {
        shimmer: {
          "0%": { backgroundPosition: "200% 0" },
          "100%": { backgroundPosition: "-200% 0" },
        },
        fadeIn: {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        staggerIn: {
          from: { opacity: "0", transform: "translateY(10px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "bounce-subtle": {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-4px)" },
        },
      },
      // Safe-area padding utilities (used by PWA base)
      spacing: {
        "safe-top": "env(safe-area-inset-top, 0px)",
        "safe-bottom": "env(safe-area-inset-bottom, 0px)",
      },
    },
  },
  plugins: [],
};
