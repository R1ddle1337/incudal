/**
 * 公共计费计算模块
 * 所有涉及价格、日价、差价、剩余价值的计算必须使用本模块的方法
 * 确保全系统计算逻辑一致
 *
 * 金额运算统一使用 Prisma.Decimal（decimal.js 定点数），避免 JS 浮点
 * 在多步乘除链路中累积误差导致差价/退款 ±0.01 偏差与对账不平。
 */

import { Prisma } from '@prisma/client'

const Decimal = Prisma.Decimal

/** 四舍五入到 2 位小数并转为 number（用于金额） */
function round2(value: InstanceType<typeof Prisma.Decimal>): number {
  return Number(value.toDecimalPlaces(2, Prisma.Decimal.ROUND_HALF_UP))
}

/** 四舍五入到 4 位小数并转为 number（用于日价展示） */
function round4(value: InstanceType<typeof Prisma.Decimal>): number {
  return Number(value.toDecimalPlaces(4, Prisma.Decimal.ROUND_HALF_UP))
}

// ==================== 周期天数常量 ====================

/**
 * 标准周期天数
 * 统一定义：1个月 = 31 天
 * 月付: 31 天
 * 季付: 31 * 3 = 93 天
 * 半年付: 31 * 6 = 186 天
 * 年付: 31 * 12 = 372 天
 */
const CYCLE_DAYS: Record<number, number> = {
  1: 31,      // 月付
  3: 93,      // 季付
  6: 186,     // 半年付
  12: 372     // 年付
}

// ==================== 基础计算函数 ====================

/**
 * 获取周期天数
 * @param billingCycle 计费周期（月数）
 * @returns 周期天数
 */
export function getCycleDays(billingCycle: number): number {
  return CYCLE_DAYS[billingCycle] || (billingCycle * 31)
}

/**
 * 计算日价
 * @param price 周期价格（元）
 * @param billingCycle 计费周期（月数）
 * @returns 日价（元）
 */
export function calculateDailyPrice(price: number, billingCycle: number): number {
  const cycleDays = getCycleDays(billingCycle)
  return price / cycleDays
}

/**
 * 计算月价
 * @param price 周期价格（元）
 * @param billingCycle 计费周期（月数）
 * @returns 月价（元）
 */
export function calculateMonthlyPrice(price: number, billingCycle: number): number {
  const cycle = Math.max(billingCycle || 1, 1) // 防止除零
  return price / cycle
}

/**
 * 计算实际支付价格（应用折扣后）
 * @param originalPrice 原价（元）
 * @param discountRate 折扣率（0-1，如 0.05 表示 5% 折扣）
 * @returns 折扣后价格（元）
 */
export function calculateDiscountedPrice(originalPrice: number, discountRate: number): number {
  return round2(new Decimal(originalPrice).times(new Decimal(1).minus(discountRate)))
}

/**
 * 计算折扣金额
 * @param originalPrice 原价（元）
 * @param discountRate 折扣率（0-1）
 * @returns 折扣金额（元）
 */
export function calculateDiscountAmount(originalPrice: number, discountRate: number): number {
  return round2(new Decimal(originalPrice).times(discountRate))
}

// ==================== 剩余天数计算 ====================

/**
 * 计算剩余天数（向上取整）
 * @param expiresAt 到期时间
 * @param now 当前时间（可选，默认为当前）
 * @returns 剩余天数（>=0）
 */
export function calculateRemainingDays(expiresAt: Date, now: Date = new Date()): number {
  const expiresDate = new Date(expiresAt)
  const remainingMs = expiresDate.getTime() - now.getTime()
  return Math.max(0, Math.ceil(remainingMs / (24 * 60 * 60 * 1000)))
}

/**
 * 计算剩余天数（精确到小数）
 * @param expiresAt 到期时间
 * @param now 当前时间（可选）
 * @returns 剩余天数（精确）
 */
export function calculateRemainingDaysPrecise(expiresAt: Date, now: Date = new Date()): number {
  const expiresDate = new Date(expiresAt)
  const remainingMs = expiresDate.getTime() - now.getTime()
  return Math.max(0, remainingMs / (24 * 60 * 60 * 1000))
}

// ==================== 剩余价值计算 ====================

/**
 * 计算剩余价值
 * 公式: 日价 × 剩余天数
 * 
 * @param price 周期价格（元，原价）
 * @param billingCycle 计费周期（月数）
 * @param remainingDays 剩余天数
 * @param discountRate 折扣率（0-1，可选）
 * @returns 剩余价值（元）
 */
export function calculateRemainingValue(
  price: number,
  billingCycle: number,
  remainingDays: number,
  discountRate: number = 0
): number {
  // 使用折扣后的价格计算剩余价值
  const effectivePrice = discountRate > 0
    ? calculateDiscountedPrice(price, discountRate)
    : price
  // 全程 Decimal：effectivePrice / cycleDays * remainingDays，避免日价浮点丢精度
  const cycleDays = getCycleDays(billingCycle)
  return round2(new Decimal(effectivePrice).div(cycleDays).times(remainingDays))
}

/**
 * 计算安全的剩余价值退款金额
 * 确保退款金额不超过实际支付金额
 * 
 * @param price 周期价格（元，原价）
 * @param billingCycle 计费周期（月数）
 * @param remainingDays 剩余天数
 * @param discountRate 折扣率（0-1）
 * @param maxRefundable 最大可退款金额（可选，用于限制）
 * @returns 安全的退款金额（元）
 */
export function calculateSafeRefundAmount(
  price: number,
  billingCycle: number,
  remainingDays: number,
  discountRate: number = 0,
  maxRefundable?: number
): number {
  const effectivePrice = discountRate > 0
    ? calculateDiscountedPrice(price, discountRate)
    : price

  // 计算剩余价值
  const cycleDays = getCycleDays(billingCycle)
  const remainingRatio = Math.min(remainingDays / cycleDays, 1) // 比例不能超过 1
  const refundAmount = round2(new Decimal(effectivePrice).times(remainingRatio))

  // 如果提供了最大可退款金额，取较小值
  if (maxRefundable !== undefined) {
    return Math.min(refundAmount, maxRefundable)
  }

  return refundAmount
}

// ==================== 差价计算 ====================

/**
 * 计算方案切换差价
 * 公式: (新方案日价 - 旧方案日价) × 剩余天数
 * 
 * 重要：
 * - 如果用户原本用优惠码购买，剩余价值应该用折扣后价格计算
 * - 新方案费用也应该用折扣后价格计算
 * - 确保公平性：用户实际支付了多少，剩余价值就按比例退多少
 * 
 * @param oldPrice 旧方案周期价格（元）
 * @param oldBillingCycle 旧方案计费周期
 * @param newPrice 新方案周期价格（元）
 * @param newBillingCycle 新方案计费周期
 * @param remainingDays 剩余天数
 * @param discountRate 折扣率（0-1，应用于新旧方案）
 * @returns 差价（正数=补交，负数=退款）
 */
export function calculatePriceDiff(
  oldPrice: number,
  oldBillingCycle: number,
  newPrice: number,
  newBillingCycle: number,
  remainingDays: number,
  discountRate: number = 0
): number {
  // 应用折扣后的实际价格
  const actualOldPrice = discountRate > 0
    ? calculateDiscountedPrice(oldPrice, discountRate)
    : oldPrice
  const actualNewPrice = discountRate > 0
    ? calculateDiscountedPrice(newPrice, discountRate)
    : newPrice

  // 全程 Decimal 计算日价与差价，避免浮点累积误差
  const oldDailyPrice = new Decimal(actualOldPrice).div(getCycleDays(oldBillingCycle))
  const newDailyPrice = new Decimal(actualNewPrice).div(getCycleDays(newBillingCycle))

  // 差价 = (新日价 - 旧日价) × 剩余天数
  const priceDiff = newDailyPrice.minus(oldDailyPrice).times(remainingDays)

  // 最低金额门槛：低于 0.01 元按 0 处理
  return priceDiff.abs().lessThan(0.01) ? 0 : round2(priceDiff)
}

/**
 * 计算完整的方案切换结果
 * 包含所有计算细节，供前端展示和后端处理
 */
export interface PlanChangeCalcResult {
  /** 旧方案日价（元） */
  oldDailyPrice: number
  /** 新方案日价（元） */
  newDailyPrice: number
  /** 剩余价值（元，折扣后） */
  remainingValue: number
  /** 新方案费用（元，折扣后） */
  newPlanCost: number
  /** 折扣金额（元） */
  discountAmount: number
  /** 差价（元，正数=补交，负数=退款） */
  priceDiff: number
  /** 是否升级 */
  isUpgrade: boolean
}

export function calculatePlanChangeDetails(
  oldPrice: number,
  oldBillingCycle: number,
  newPrice: number,
  newBillingCycle: number,
  remainingDays: number,
  discountRate: number = 0
): PlanChangeCalcResult {
  // 计算折扣后的价格
  const actualOldPrice = discountRate > 0
    ? calculateDiscountedPrice(oldPrice, discountRate)
    : oldPrice
  const actualNewPrice = discountRate > 0
    ? calculateDiscountedPrice(newPrice, discountRate)
    : newPrice

  // 全程 Decimal 计算日价
  const oldDailyPrice = new Decimal(actualOldPrice).div(getCycleDays(oldBillingCycle))
  const newDailyPrice = new Decimal(actualNewPrice).div(getCycleDays(newBillingCycle))

  // 剩余价值 = 旧日价 × 剩余天数
  const remainingValueDec = oldDailyPrice.times(remainingDays)
  const remainingValue = round2(remainingValueDec)

  // 新方案费用 = 新日价 × 剩余天数
  const newPlanCostDec = newDailyPrice.times(remainingDays)
  const newPlanCost = round2(newPlanCostDec)

  // 折扣金额（基于新方案原价）
  const discountAmount = discountRate > 0
    ? round2(new Decimal(newPrice).div(getCycleDays(newBillingCycle)).times(remainingDays).times(discountRate))
    : 0

  // 差价
  const priceDiffDec = newPlanCostDec.minus(remainingValueDec)
  const finalPriceDiff = priceDiffDec.abs().lessThan(0.01) ? 0 : round2(priceDiffDec)

  return {
    oldDailyPrice: round4(oldDailyPrice),
    newDailyPrice: round4(newDailyPrice),
    remainingValue,
    newPlanCost,
    discountAmount,
    priceDiff: finalPriceDiff,
    isUpgrade: newDailyPrice.greaterThan(oldDailyPrice)
  }
}

// ==================== 续费计算 ====================

/**
 * 计算续费金额
 * @param monthlyPrice 月价（元）
 * @param months 续费月数
 * @param discountRate 折扣率（0-1）
 * @returns { originalAmount, discountAmount, finalAmount }
 */
export function calculateRenewAmount(
  monthlyPrice: number,
  months: number,
  discountRate: number = 0
): { originalAmount: number; discountAmount: number; finalAmount: number } {
  const originalAmountDec = new Decimal(monthlyPrice).times(months)
  const originalAmount = round2(originalAmountDec)
  const discountAmountDec = discountRate > 0
    ? originalAmountDec.times(discountRate)
    : new Decimal(0)
  const discountAmount = round2(discountAmountDec)
  const finalAmount = round2(originalAmountDec.minus(discountAmountDec))

  return { originalAmount, discountAmount, finalAmount }
}

// ==================== 辅助函数 ====================

/**
 * 添加月份到日期
 * 统一按天数计算：1个月 = 31 天
 * @param date 基准日期
 * @param months 月数
 * @returns 新日期
 */
export function addMonths(date: Date, months: number): Date {
  const daysToAdd = months * 31
  const result = new Date(date)
  result.setDate(result.getDate() + daysToAdd)
  return result
}
