import {
  VK,
  Keyboard,
  MessageContext,
  ContextDefaultState,
  Upload,
  Objects,
} from "vk-io";
import _ from "lodash";

const vk = new VK({
  token: process.env.BOT_TOKEN || "",
});

vk.updates.on("message_new", async (context) => {
  if (context.$groupId === parseInt(process.env["OLD_BOT_ID"]!))
    return context.send({
      message: `Используйте нового бота: ${process.env["CURRENT_BOT_URL"]}`,
    });

  if (context.text == "Начать")
    return context.send({
      message: `👇 Просто отправь картинки сюда, и бот их перекинет. Бот может пересылать картинки из обычных и пересланных сообщений.`,
      keyboard: Keyboard.builder().textButton({
        label: "Начать",
        payload: {
          command: "Начать",
        },
      }),
    });

  try {
    let photosSent = false;

    const msg = (
      await vk.api.messages.getById({
        message_ids: context.id,
      })
    ).items[0];

    if (await processFwds(context, msg)) {
      photosSent = true;
    }

    if (!photosSent) {
      context.send(
        "❌ Я не вижу изображений. Бот может пересылать изображения из обычных и пересланных сообщений."
      );
    }
  } catch (err) {
    console.error(err);
    context.send("❌ Произошла неизвестная ошибка. Сообщите разработчику об этой проблеме: https://vk.me/nikitabogun");
  }
});

async function processFwds(
  context: MessageContext<ContextDefaultState>,
  msg: Objects.MessagesMessage
): Promise<boolean> {
  let photosSent = false;

  if (await processPhotos(context, msg)) {
    photosSent = true;
  }

  if (msg.fwd_messages && msg.fwd_messages.length > 0) {
    for (const forward of msg.fwd_messages) {
      if (await processFwds(context, forward)) photosSent = true;
    }
  }

  return photosSent;
}

async function processPhotos(
  initialContext: MessageContext<ContextDefaultState>,
  msg: Objects.MessagesMessage
): Promise<boolean> {
  const attachments = msg.attachments.filter(
    (attachment) => attachment.type === "photo"
  );

  if (attachments.length === 0) return false;

  if (attachments) {
    let photoArray = [];

    photoArray = attachments.map((photo) => {
      const accessKey = photo.photo.access_key
        ? `_${photo.photo.access_key}`
        : "";

      return `${photo.type}${photo.photo.owner_id}_${photo.photo.id}${accessKey}`;
    });

    if (photoArray.length > 0) {
      await initialContext.send({
        attachment: photoArray.join(","),
      });

      return true;
    }
  }
  return false;
}

vk.updates
  .start()
  .then(() => console.log("Bot started"))
  .catch(console.error);
