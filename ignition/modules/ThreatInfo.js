const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("DeployThreatInfo", (m) => {
  const ThreatInfo = m.contract("ThreatInfo", [
    /* 初始化合約時需要的參數，例如最大報告次數和報告窗口時間 */
    5, // 最大報告次數
    86400 // 報告窗口（以秒為單位，例如 24 小時 = 86400 秒）
  ]);
  return { ThreatInfo };
});

// 部署腳本更新說明：
// - 新合約名稱為 ThreatInfo，並使用與 AntiScalperTicket 合約不同的初始化參數。
// - 根據需求添加必要的事件和函數，確保與前端交互邏輯保持一致。