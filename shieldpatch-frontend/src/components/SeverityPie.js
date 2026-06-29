// src/components/SeverityPie.js
import React, { useEffect, useState } from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend
} from "recharts";

const COLORS = {
  CRITICAL: "#b22222",
  HIGH: "#ff6b6b",
  LOW: "#8bc34a",      // brighter green for visibility
  MEDIUM: "#f6d365",
  UNKNOWN: "#777777",
};

function CenterLabel({ total }) {
  // Render an SVG text (center of chart). Recharts places children under same SVG so coordinates work.
  return (
    <text
      x="50%"
      y="50%"
      textAnchor="middle"
      dominantBaseline="middle"
      style={{ fill: "#f3f6fb", fontSize: 20, fontWeight: 700 }}
    >
      {total}
      <tspan
        x="50%"
        dy="1.6em"
        style={{ fontSize: 12, fontWeight: 400, fill: "#b7c6d9" }}
      >
        total
      </tspan>
    </text>
  );
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const p = payload[0];
  return (
    <div
      style={{
        background: "#071018",
        border: "1px solid rgba(255,255,255,0.06)",
        padding: 8,
        color: "#e6f1ff",
        fontSize: 13,
        borderRadius: 6,
        boxShadow: "0 6px 18px rgba(0,0,0,0.6)",
      }}
    >
      <div style={{ fontWeight: 700 }}>{p.name}</div>
      <div style={{ marginTop: 4 }}>
        {p.value} items — {(p.payload?.pct ?? 0).toFixed(1)}%
      </div>
    </div>
  );
}

export default function SeverityPie({
  apiBase = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000",
  donut = true,
}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);

    fetch(`${apiBase}/api/vulnlookup/stats/severity`)
      .then((r) => r.json())
      .then((json) => {
        if (!mounted) return;

        const counts = json?.counts || {};
        const total =
          json?.total ??
          Object.values(counts).reduce(
            (acc, n) => acc + (Number(n) || 0),
            0
          );

        // keep consistent order for legend and colors
        const order = ["CRITICAL", "HIGH", "LOW", "MEDIUM"];

        const slices = order
          .map((k) => ({
            name: k,
            value: Number(counts[k] || 0),
          }))
          .filter((d) => d.value > 0)
          .map((d) => ({
            ...d,
            pct: total > 0 ? (d.value / total) * 100 : 0,
          }));

        setData({ slices, total });
      })
      .catch((err) => setError(err.message || String(err)))
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [apiBase]);

  if (loading) {
    return (
      <div
        style={{
          padding: 24,
          background: "#071018",
          borderRadius: 10,
          color: "#9fb7c9",
        }}
      >
        Loading severity distribution...
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          padding: 16,
          borderRadius: 8,
          background: "#071018",
          color: "#ffb3b3",
        }}
      >
        Failed to load severity stats: {error}
      </div>
    );
  }

  if (!data || !data.slices.length) {
    return (
      <div
        style={{
          padding: 16,
          borderRadius: 8,
          background: "#071018",
          color: "#9fb7c9",
        }}
      >
        No severity data available.
      </div>
    );
  }

  /**
   * Custom label renderer: places labels outside the donut with a small offset,
   * uses percent provided by Recharts to avoid recomputing. This helps the tiny LOW slice label be visible.
   */
  const renderCustomizedLabel = ({
    cx,
    cy,
    midAngle,
    innerRadius,
    outerRadius,
    percent,
    index,
    name,
    value
  }) => {
    const RAD = Math.PI / 180;
    // put label outside outerRadius
    const labelRadius = outerRadius + 20;
    const x = cx + labelRadius * Math.cos(-midAngle * RAD);
    const y = cy + labelRadius * Math.sin(-midAngle * RAD);
    // anchor depending on left/right half
    const textAnchor = x > cx ? "start" : "end";
    const display = `${value} (${Math.round(percent * 100)}%)`;
    return (
      <text
        x={x}
        y={y}
        fill="#f3f6fb"
        textAnchor={textAnchor}
        dominantBaseline="central"
        style={{ fontSize: 12, fontWeight: 700 }}
      >
        {name === "LOW" ? (
          // use a small green color for count so it's visible
          <tspan style={{ fill: "#8bc34a" }}>{display}</tspan>
        ) : (
          display
        )}
      </text>
    );
  };

  return (
    <div
      style={{
        padding: 18,
        borderRadius: 10,
        background: "#071018",
        boxShadow: "inset 0 0 0 1px rgba(255,255,255,0.02)",
      }}
    >
      <div style={{ color: "#cfe6ff", marginBottom: 10, fontSize: 15 }}>
        Pie Chart
      </div>

      <div style={{ height: 320 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip content={<CustomTooltip />} />

            <Pie
              data={data.slices}
              dataKey="value"
              nameKey="name"
              innerRadius={donut ? "60%" : 0}
              outerRadius="85%"
              cx="50%"
              cy="50%"
              paddingAngle={2}
              stroke="rgba(0,0,0,0.15)"
              isAnimationActive={true}
              labelLine={true}               // draw lines to outside labels
              label={renderCustomizedLabel}  // custom outside label renderer
            >
              {data.slices.map((entry, i) => (
                <Cell
                  key={`cell-${i}`}
                  fill={COLORS[entry.name] || COLORS.UNKNOWN}
                  stroke="rgba(0,0,0,0.25)"
                />
              ))}

              {/* center total label */}
              <CenterLabel total={data.total} />
            </Pie>

            <Legend
              verticalAlign="bottom"
              align="center"
              iconType="square"
              wrapperStyle={{
                color: "#e7f4ff",
                paddingTop: 12,
              }}
              formatter={(value) => {
                const item = data.slices.find((s) => s.name === value);
                const count = item ? item.value : 0;
                return (
                  <span style={{ color: "#f3f6fb", fontWeight: 700 }}>
                    {value}
                    <span
                      style={{
                        color: "#9fb7c9",
                        fontWeight: 400,
                        marginLeft: 8,
                      }}
                    >
                      {count}
                    </span>
                  </span>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}