import React from 'react';

/**
 * Standardized Recharts SOC Dark Theme Tooltip Configuration.
 * Ensures consistent dark surfaces, high-contrast crisp light text,
 * and eliminates any default dark/black inherited text colors.
 */
export const chartTooltipProps = {
  contentStyle: {
    backgroundColor: '#0D1117',
    border: '1px solid rgba(255, 255, 255, 0.15)',
    borderRadius: '10px',
    padding: '10px 14px',
    boxShadow: '0 8px 30px rgba(0, 0, 0, 0.7)',
    color: '#FFFFFF',
    fontSize: '12px',
  },
  labelStyle: {
    color: '#F1F5F9',
    fontWeight: 600,
    fontSize: '11px',
    marginBottom: '6px',
    letterSpacing: '0.04em',
    textTransform: 'uppercase' as const,
  },
  itemStyle: {
    color: '#38BDF8',
    fontSize: '12px',
    fontWeight: 500,
    paddingTop: '2px',
    paddingBottom: '2px',
  },
  cursor: {
    fill: 'rgba(56, 189, 248, 0.05)',
    stroke: 'rgba(56, 189, 248, 0.3)',
    strokeDasharray: '3 3',
  },
};

