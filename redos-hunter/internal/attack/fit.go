package attack

import "math"

// GrowthFit 增长曲线拟合结果。
type GrowthFit struct {
	Kind        string  `json:"kind"` // exponential | polynomial | linear | unknown
	Exponent    float64 `json:"exponent"`
	Base        float64 `json:"base"`
	RSquared    float64 `json:"r_squared"`
	SuperLinear bool    `json:"super_linear"`
}

// FitGrowth 对 (n, steps) 点做拟合：分别拟合 log(steps)=a*n+b（指数）
// 与 log(steps)=k*log(n)+b（多项式），取 R² 更高者。
func FitGrowth(pts []Point) GrowthFit {
	fit := GrowthFit{Kind: "unknown"}
	var xs, ys []float64
	for _, p := range pts {
		if p.Steps <= 1 {
			continue
		}
		xs = append(xs, float64(p.N))
		ys = append(ys, math.Log(float64(p.Steps)))
	}
	if len(xs) < 3 {
		return fit
	}

	a, _, rExp := linReg(xs, ys)
	logX := make([]float64, len(xs))
	for i := range xs {
		logX[i] = math.Log(xs[i])
	}
	k, bp, rPoly := linReg(logX, ys)

	fit.RSquared = math.Max(rExp, rPoly)
	if rExp >= rPoly && a > 0.05 {
		fit.Kind = "exponential"
		fit.Base = math.Exp(a)
		fit.Exponent = a
		fit.SuperLinear = true
	} else if k > 1.2 {
		fit.Kind = "polynomial"
		fit.Exponent = k
		fit.Base = math.Exp(bp)
		fit.SuperLinear = true
	} else {
		fit.Kind = "linear"
		fit.Exponent = k
	}
	return fit
}

// linReg 最小二乘 y=a*x+b，返回 a,b 与 R²。
func linReg(x, y []float64) (a, b, r2 float64) {
	n := float64(len(x))
	var sx, sy, sxx, sxy float64
	for i := range x {
		sx += x[i]
		sy += y[i]
		sxx += x[i] * x[i]
		sxy += x[i] * y[i]
	}
	den := n*sxx - sx*sx
	if math.Abs(den) < 1e-12 {
		return 0, sy / n, 0
	}
	a = (n*sxy - sx*sy) / den
	b = (sy - a*sx) / n
	var ssRes, ssTot float64
	mean := sy / n
	for i := range x {
		pred := a*x[i] + b
		ssRes += (y[i] - pred) * (y[i] - pred)
		ssTot += (y[i] - mean) * (y[i] - mean)
	}
	if ssTot < 1e-12 {
		return a, b, 1
	}
	r2 = 1 - ssRes/ssTot
	if r2 < 0 {
		r2 = 0
	}
	return a, b, r2
}
