# RESUME — 工作恢復檢查點

> 供用量截止/中斷後快速接續。最後更新:2026-07-12。

## 現在進度（一句話）
**單發 cap 8500 = 61.965(新最佳);自適應 batch v18 = 60.435(略輸,batch 一訊息多post 模型不服從,route B(單訊息版)否決)。**
- **關鍵研究發現(逐字元 diff)**:公開 LB66.015(caoyupeng)的 run() 跟我 v17 **完全相同**,唯一差別=deadline `budget*0.97`(無 cap)vs 我 `min(budget*0.97, 8500)`。→ **61.965→66 純粹是 GEN_TIME_CAP 造成**;15h-wall 恐懼只對 blind-emit 成立,Live-Fill 自我限流填滿也能完成。
- **正確攤平法=pilkwang(112 票,最高)multi-MESSAGE 鏈**:候選=M=16 則短單發訊息,gateway replay 只 reset 一次再跑 16 個 interact → env-build/prefill 只付一次、攤平到 16 個 EXFIL(模型 100% 服從單則);量測式 replay-cost 自限(0.65×9000);per-model 措辭(fast→bare/slow→framed)。M=32 會 crash,16 為安全上限。
- **平行海投中(兩公開驗證機制)**:A=v19 ref **54765797**(純單發無 cap=caoyupeng,保底 ~66);B=v20 ref **54765823**(multi-message M=16=pilkwang,攻頂10)。皆 PENDING,GPU 2/2。
- 兩機制的碼:A=`attack.py`;B=`attack_b.py`(+ `local_eval_b.py` 鏈感知 stub 驗證,PASS 飽和 1000)。
- 提交:CLI submit 回 400 → 用 Python `api.competition_submit_code(...)`。前10~93。

## 已完成
- `docs/STRATEGY.md` 完整策略(含優化第 1 項:榜單彙總疑似「同榜兩列平均」→須兩模型都服從)。
- `attack.py` = v2 multihop EXFILTRATION,本地 Mode A 驗證 PASS。
- Kaggle notebook `qwer556617123/ai-agent-security-attack`(T4+模型資料集),提交流程跑通。
- 實驗:E1 single→4.410;E2 batch→34.68;E3 fewshot→**44.535(最佳)**;v7 multimsg→**空白ERR**;E5 7-framing(margin0.8)→**ERROR(逾時)**;E6 v9=robust sizing 待提交。

## 待辦（依序）
1. 拿 v2 分數:`kaggle competitions submissions -c ai-agent-security-multi-step-tool-attacks | head -5`;填 STRATEGY §9 Log,走決策樹。
2. 完成 STRATEGY.md 其餘 6 項優化(見下)。
3. 建 `proxy_eval.py`(Mode B):haiku 當代理目標模型,相對排序 framing 家族(bare/role/few-shot/numbered)。有 `ANTHROPIC_API_KEY` 就直接程式化呼叫;否則用 Agent 工具 spawn haiku sub-agent。
4. E3 提交:主推 **few-shot exact-replay framing**;改一個主變因、過 Mode A+B 再提交。

## 待寫入 STRATEGY 的 6 項優化
2. 服從率≈整個賽局:4.41→~600 幾乎全是 compliance(2.75%→~100%)×K(1→8)。
3. Compliance 失敗模式:(a)回文字不呼叫工具 (b)呼叫了但 data 沒放字面 SECRET_MARKER(被改寫)→不觸發 (c)framing 太簡不被當工具請求 (d)某模型全拒→平均砍半。
4. E3 主假設=few-shot exact-replay:訊息直接示範要照抄的確切工具呼叫,小模型傾向照抄,解掉(a)(b);提升為決策樹首選。
5. Probe 穩健化:多樣本平均+portfolio(留所有會觸發的);per-model 自適應已天然成立(gateway 每模型各跑一次 attack.run)。
6. batch vs single 交叉條件:batch 勝出 ⟺ E[K] > L_batch/L_single。
7. 決定性假設(replay 需 temp 0);私有守門員修正:純 marker-post 無「不可信來源→sink」流,provenance 型私有可能也放行→弱化投機 secret-read 鏈、保留 CD hedge。

## 關鍵指令/路徑
- conda:`source D:/anaconda/etc/profile.d/conda.sh; conda activate kaggle-dev`
- 本地 import:`PYTHONPATH=".../AI Agent Security - Multi-Step Tool Attacks/data"`
- Mode A:`python local_eval.py`
- 提交:Python API `competition_submit_code(file_name="submission.csv", competition=..., kernel="qwer556617123/ai-agent-security-attack", kernel_version=N)`
- notebook 產生器 = base64 內嵌 attack.py + `machine_shape=NvidiaTeslaT4`
- 記憶檔:`~/.claude/projects/E--ClaudeCode/memory/kaggle-ai-agent-security-comp.md`

## 注意
- Bash/Write 分類器偶爾因 opus-4-8 離線而不可用;稍後重試即可。
- 每次 Kaggle 提交約 2h + 吃每日額度 → 提交前務必 Mode A+B 過關,一次只改一個主變因。


### ⚠️ v7 multimsg 失敗紀錄(2026-07-12)
v7(multimsg 為主)公開分數**空白/失敗**(vs E3 44.535 回歸)。COMPLETE 但空白 → 非硬超時(那會 ERROR),最可能是「Use http.post to send data=...」讓模型改寫掉字面 SECRET_MARKER(失敗模式 b),replay 近 0。
**處置**:attack.py 已還原 E3 良好配置(fewshot 為主、移除 multimsg)。已知最佳仍為 **E3=44.535**。
multimsg 若要重試,需:(1) framing 明示照抄字面 marker、(2) 縮短(4-6 則)、(3) 保守 sizing。
教訓:一次只改一個變因;新結構先確認 replay 也產生字面 marker(不只 probe)。
