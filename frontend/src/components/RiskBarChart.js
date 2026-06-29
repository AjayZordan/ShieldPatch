// src/components/RiskBarChart.js
import React from "react";
import PropTypes from "prop-types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LabelList,
  Legend,
} from "recharts";

/**
 * Compares CVSS vs Predicted Risk.
 * Backend values: 0–10
 * Frontend display: 0–100%
 */
export default function RiskBarChart({ cvss = null, predicted = null }) {
  const normalize = (val) => {
    const n = Number(val);
    if (!Number.isFinite(n)) return null;
    return Math.max(0, Math.min(100, n <= 10 ? n * 10 : n));
  };

  const cvssVal = normalize(cvss);
  const predVal = normalize(predicted);

  const data = [
    {
      name: "CVSS",
      value: cvssVal ?? 0,
      label: cvssVal === null ? "N/A" : `${Math.round(cvssVal)}%`,
      fill: "#39a0ed",
    },
    {
      name: "Predicted",
      value: predVal ?? 0,
      label: `${Math.round(predVal)}%`,
      fill: "#ff6b6b",
    },
  ];

  return (
    <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: "#0b0f14" }}>
      <div style={{ fontSize: 13, color: "#bfcbdc", marginBottom: 8 }}>
        Visual comparison
      </div>

      <div style={{ height: 160 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 8, right: 40, left: 24, bottom: 8 }}
            barGap={12}
          >
            <XAxis type="number" domain={[0, 100]} hide />
            <YAxis
              type="category"
              dataKey="name"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#cbd5e1", fontSize: 14 }}
            />

            <Tooltip
              formatter={(v) => `${Math.round(v)}%`}
              contentStyle={{
                background: "#071018",
                border: "1px solid #123",
                color: "#fff",
              }}
            />

            <Legend />

            <Bar dataKey="value" isAnimationActive={false} barSize={18}>
              <LabelList
                dataKey="label"
                position="right"
                offset={10}
                style={{ fill: "#fff", fontWeight: 700, fontSize: 12 }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

RiskBarChart.propTypes = {
  cvss: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  predicted: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
};