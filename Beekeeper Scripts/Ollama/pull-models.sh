#!/bin/sh
# Pull every Ollama model named by a Beelzebub service config.
#
# The service YAML is the single source of truth for which model a port uses.
# Beelzebub does not expand environment variables inside service configs (only
# core config has BEELZEBUB_* overrides), so llmModel has to be a literal
# there. Rather than repeat that string in docker-compose.yml or .env - two
# places to keep in step, and a silent runtime failure when they drift - this
# reads the model names back out of the configs and pulls each one.
#
# Side benefit: point another service at Ollama later and its model is pulled
# automatically, with no change needed here or in docker-compose.yml.
set -eu

CONFIG_DIR="${CONFIG_DIR:-/configurations/services}"

models=""
for f in "$CONFIG_DIR"/*.yaml; do
    [ -f "$f" ] || continue

    # Skip services not pointed at Ollama (e.g. the ones still set to openai).
    grep -qE '^[[:space:]]*llmProvider:[[:space:]]*"?ollama"?[[:space:]]*$' "$f" || continue

    # Take everything after the first colon, so model names containing a colon
    # (llama3.2:3b) survive; then strip comments, quotes and surrounding space.
    model=$(grep -m1 -E '^[[:space:]]*llmModel:' "$f" \
            | cut -d: -f2- \
            | sed -e 's/#.*$//' -e 's/"//g' -e "s/'//g" \
            | awk '{$1=$1; print}')

    if [ -z "$model" ]; then
        echo "ERROR: $(basename "$f") sets llmProvider: ollama but has no llmModel" >&2
        exit 1
    fi

    # Two services may share a model; only pull it once.
    case " $models " in
        *" $model "*) continue ;;
    esac
    models="$models $model"
    echo "Found model '$model' in $(basename "$f")"
done

if [ -z "$models" ]; then
    echo "No service uses llmProvider: ollama - nothing to pull."
    exit 0
fi

for model in $models; do
    echo "Pulling '$model'..."
    ollama pull "$model"
done

echo "Model pull complete."
