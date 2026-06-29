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
 * Simple bar chart that compares CVSS (0-10) scaled to 0-100, and Predicted Risk (0-100).
 * Props:
 *  - cvss: number (0-10 or 0-100). If 0-10 it's auto-scaled to 0-100.
 *  - predicted: number (0-100)
 */
export default function RiskBarChart({ cvss = null, predicted = null }) {
  // Normalize cvss to 0-100 if it's in 0-10 range
  let cvssVal = cvss === null || cvss === undefined ? null : Number(cvss);
  if (!Number.isFinite(cvssVal)) cvssVal = null;
  if (cvssVal !== null && cvssVal <= 10) cvssVal = Math.max(0, Math.min(10, cvssVal)) * 10;

  const predVal = predicted === null || predicted === undefined ? 0 : Number(predicted);

  // explicit fields so each bar is independent (no overlapping trick)
  const data = [
    {
      name: "CVSS",
      cvss: cvssVal !== null ? Math.max(0, Math.min(100, Math.round(cvssVal))) : 0,
      predicted: 0,
      label: cvssVal === null ? "N/A" : `${Math.round(cvssVal)}%`,
    },
    {
      name: "Predicted",
      cvss: 0,
      predicted: Math.max(0, Math.min(100, Math.round(predVal))),
      label: `${Math.round(predVal)}%`,
    },
  ];

  const darkBg = "#0b0f14";
  const cvssColor = "#39a0ed";
  const predColor = "#ff6b6b";

  return (
    <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: darkBg }}>
      <div style={{ fontSize: 13, color: "#bfcbdc", marginBottom: 8 }}>Visual comparison</div>
      <div style={{ height: 160 }}>
        <ResponsiveContainer width="100%" height="100%">
          {/* layout vertical (horizontal bars) */}
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 8, right: 40, left: 24, bottom: 8 }} // right margin increased for labels
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
              cursor={{ fill: "rgba(255,255,255,0.03)" }}
              contentStyle={{ background: "#071018", border: "1px solid #123", color: "#fff" }}
            />
            <Legend
              wrapperStyle={{ bottom: -4 }}
              payload={[
                { value: "CVSS (scaled)", type: "square", color: cvssColor },
                { value: "Predicted risk", type: "square", color: predColor },
              ]}
            />

            <Bar dataKey="cvss" fill={cvssColor} isAnimationActive={false} barSize={18}>
              <LabelList
                dataKey="label"
                position="right"
                offset={10} // push labels a bit to the right so they're not clipped
                style={{ fill: "#fff", fontWeight: 700, fontSize: 12 }}
              />
            </Bar>

            <Bar dataKey="predicted" fill={predColor} isAnimationActive={false} barSize={18}>
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

      <div style={{ marginTop: 8, display: "flex", gap: 10, color: "#9fb7c9", fontSize: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 10, height: 10, background: cvssColor, borderRadius: 2 }} /> CVSS (scaled)
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 10, height: 10, background: predColor, borderRadius: 2 }} /> Predicted risk
        </div>
      </div>
    </div>
  );
}

RiskBarChart.propTypes = {
  cvss: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  predicted: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
};