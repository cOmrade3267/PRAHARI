# Prahari — On-Device ML (second opinion)

Trains a tiny permission-based classifier on **NATICUSdroid** and exports a quantized
`model.tflite` + `features.json` that run **fully offline** on the phone. This is PS stretch #13,
and it stays a *second opinion*: the rule engine remains the source of risk explanations
(`../PLAN.md §5.7`). If rules say Low but the model says "likely harmful", show a soft nudge —
never let the model override the explained rule score.

```
ml/
  train_naticusdroid.py   one-time trainer -> out/model.tflite, out/features.json, out/metrics.json
  requirements.txt        training-only deps (the phone needs none of them)
  out/                    created on run (git-ignore it)
```

## Offline framing (so this doesn't break the "strictly offline" claim)

- **Training** runs once on your laptop and needs the network only to *download the public dataset*.
- **Inference** runs on-device with the bundled `.tflite` — **no network, no `INTERNET` permission.**
- The PS explicitly allows a model "trained before the event on a public permission dataset." That's exactly this.

## Run it

```bash
cd ml
python -m venv .venv
# Windows:  .venv\Scripts\activate       macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

python -I train_naticusdroid.py           # auto-downloads NATICUSdroid (UCI id 722)
# or, if you downloaded the CSV yourself:
python -I train_naticusdroid.py --csv path/to/NATICUSdroid.csv
# optional smaller model with int8 I/O:
python -I train_naticusdroid.py --int8
```

Outputs land in `ml/out/`. Copy `model.tflite` and `features.json` into the app at
`app/src/main/assets/ml/`.

> The script prints and saves **real** held-out metrics (`metrics.json`) — accuracy, precision,
> recall, F1, ROC-AUC, confusion matrix. Report those numbers, not guessed ones. Permission-only
> models on this dataset usually land high, but they **age**: accuracy drops on app populations
> newer than the 2010–2019 training data, so treat the model as a hint and retrain when you can.

## Design choices that make the Android side trivial

- **Inputs are raw 0/1** (no scaler/normaliser) → on-device you just set `1.0` for each permission
  the app has, in `features.json` order. Nothing to replicate.
- **Dynamic-range quantization by default** → int8 weights but **float32 input/output**, so you feed
  a `FloatArray` and read a `Float`. (`--int8` switches to full int8 if you want it smaller.)

## `features.json` contract

```json
{
  "input":  { "order": ["<perm-1>", "<perm-2>", "..."], "length": 86, "dtype": "float32",
              "encoding": "1.0 if the app declares/was granted this permission, else 0.0" },
  "output": { "meaning": "P(malware)", "threshold": 0.5, "best_f1_threshold": 0.xx,
              "classes": {"0":"benign","1":"malware"} }
}
```

Build the input vector in **exactly** `input.order`. ⚠️ After your first run, open `features.json`
and check how NATICUSdroid names its permissions (full `android.permission.X` vs short form) and
align your matching accordingly — the snippet below does exact-or-suffix matching to be tolerant.

## On-device integration (Kotlin)

Add the runtime (offline; the AAR is bundled in the APK):
```kotlin
implementation("org.tensorflow:tensorflow-lite:2.14.0")
```

```kotlin
class MalwareModel(context: Context) {
    private val order: List<String>
    private val interpreter: org.tensorflow.lite.Interpreter

    init {
        val featJson = context.assets.open("ml/features.json").bufferedReader().use { it.readText() }
        order = org.json.JSONObject(featJson).getJSONObject("input").getJSONArray("order")
            .let { a -> (0 until a.length()).map { a.getString(it) } }
        val model = context.assets.open("ml/model.tflite").use { it.readBytes() }
        val buf = java.nio.ByteBuffer.allocateDirect(model.size).order(java.nio.ByteOrder.nativeOrder())
        buf.put(model); buf.rewind()
        interpreter = org.tensorflow.lite.Interpreter(buf)
    }

    /** permissions = the app's declared/granted permission names. Returns P(malware) in [0,1]. */
    fun scoreMalware(permissions: Set<String>): Float {
        val input = Array(1) { FloatArray(order.size) }
        for (i in order.indices) {
            val f = order[i]
            if (permissions.any { it == f || it.endsWith(f) || f.endsWith(it) }) input[0][i] = 1f
        }
        val output = Array(1) { FloatArray(1) }
        interpreter.run(input, output)
        return output[0][0]
    }
}
```

Display as a labelled gauge beside the rule score ("Model: 0.87 likely harmful"), never as the verdict.

## Honesty notes

- No fabricated accuracy — the numbers come from your run's held-out split (`metrics.json`).
- The model never gates the demo. If a run looks weak, hide the gauge; the rules carry the product.
- NATICUSdroid is CC BY 4.0 — attribute it in the repo/report (dataset + UCI id 722).
