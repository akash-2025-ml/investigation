# Why 13 Spam Emails (Score > 0.4) Are Not Classified as Spam

## The 13 Failures
| Row | Spam Score | URLs | Why ANN Failed |
|-----|------------|------|----------------|
| 154 | **0.542** | 7 | **ABOVE 0.5!** Model is completely broken |
| 223 | 0.491 | 34 | ANN thinks high URLs = legitimate |
| 222 | 0.478 | 34 | Learned backwards pattern |
| 158 | 0.473 | 0 | Confusion zone - noisy training data |
| 58 | 0.465 | 2 | Pure model failure |
| 220 | 0.452 | 38 | Thinks 38 URLs is normal |
| 136 | 0.424 | 5 | Mislabeled training examples |
| 221 | 0.392 | 34 | High URL blindness |
| 217 | 0.410 | 38 | Backwards URL logic |
| 216 | 0.406 | 38 | Same campaign, same failure |
| 215 | 0.406 | 38 | Bulk spam = Not-Spam (!) |
| 153 | 0.403 | 7 | Edge case confusion |
| 104 | 0.480 | 5 | No clear pattern learned |

## Three Critical Failures

### 1. **No Clean Threshold**
- Row 154 has score 0.542 (>0.5) but is Not-Spam
- Meanwhile, emails with score 0.05 are Spam
- The ANN learned noise, not rules

### 2. **Backwards URL Logic**  
- 7 emails with 34-38 URLs classified as Not-Spam
- ANN learned: "many URLs = legitimate" (opposite of reality)
- Training data had max 10 URLs for Not-Spam

### 3. **Ignored Other Signals**
- Focuses 90%+ on content_spam_score
- Ignores sender reputation, authentication
- 13/15 features essentially unused

## The Brutal Truth
**Your ANN learned that spam with 38 URLs is legitimate email.** This is like a guard thinking someone with 38 knives is a chef. The model isn't just wrong - it's wrong in the most dangerous way possible.