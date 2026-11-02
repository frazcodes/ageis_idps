/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        soc: {
          dark: "#050811",
          card: "#0A0F1D",
          border: "#1E293B",
          accent: "#0284C7",
          cyan: "#38BDF8",
          emerald: "#10B981",
          crimson: "#EF4444",
          amber: "#F59E0B",
        },
      },
    },
  },
  plugins: [],
};

