from __future__ import annotations

import io
from collections.abc import Sequence

import discord

SERIES_COLORS = (
    "#2a78d6",
    "#eb6834",
    "#1baf7a",
    "#eda100",
    "#e87ba4",
    "#008300",
    "#4a3aa7",
    "#e34948",
    "#00a6d6",
    "#7a5c00",
    "#a1c935",
    "#9f55d4",
    "#c44e9b",
    "#006d77",
    "#f48c06",
    "#264653",
    "#9b5de5",
    "#ef476f",
    "#118ab2",
    "#6a994e",
)
OTHER_COLOR = "#898781"
MAX_LABEL_LENGTH = 32
MIN_DONUT_PERCENTAGE = 6


def _bounded_label(label: str) -> str:
    return label if len(label) <= MAX_LABEL_LENGTH else f"{label[:29]}..."


def _draw_ranking(axis, labels, values, colors, total_count: int) -> None:
    positions = list(range(len(values)))
    axis.barh(positions, values, color=colors, height=0.68)
    axis.set_yticks(positions, labels=labels)
    axis.invert_yaxis()
    axis.xaxis.set_visible(False)
    axis.tick_params(axis="y", length=0)
    for spine in axis.spines.values():
        spine.set_visible(False)
    largest_value = max(values)
    axis.set_xlim(0, largest_value * 1.24)
    for position, value in zip(positions, values, strict=True):
        percentage = value / total_count * 100
        axis.text(
            value + largest_value * 0.025,
            position,
            f"{value:,} | {percentage:.1f}%",
            va="center",
            fontsize=9,
        )


def _draw_donut(
    axis,
    *,
    values: list[int],
    colors: list[str],
    other_count: int,
    total_count: int,
    center_unit: str,
    title: str,
) -> None:
    donut_values = list(values)
    donut_colors = list(colors)
    if other_count:
        donut_values.append(other_count)
        donut_colors.append(OTHER_COLOR)
    labels = [""] * len(donut_values)
    if other_count:
        labels[-1] = "Other"
    _wedges, outside_labels, _percentages = axis.pie(
        donut_values,
        labels=labels,
        colors=donut_colors,
        autopct=lambda percent: (
            f"{percent:.0f}%" if percent >= MIN_DONUT_PERCENTAGE else ""
        ),
        pctdistance=0.79,
        labeldistance=1.08,
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.38, "edgecolor": "white", "linewidth": 2},
        textprops={"color": "white", "fontsize": 10, "fontweight": "bold"},
    )
    for outside_label in outside_labels:
        outside_label.set_color("#52514e")
        outside_label.set_fontweight("normal")
    axis.text(
        0,
        0,
        f"{total_count:,}\n{center_unit}",
        ha="center",
        va="center",
        fontsize=11,
    )
    axis.set_title(title, pad=12)
    axis.axis("equal")


def _draw_row_icons(axis, row_icons: Sequence[bytes | None]) -> None:
    import numpy as np
    from matplotlib.offsetbox import AnnotationBbox, OffsetImage
    from PIL import Image

    axis.tick_params(axis="y", pad=36)
    for position, data in enumerate(row_icons):
        if data is None:
            continue
        try:
            with Image.open(io.BytesIO(data)) as source:
                image = source.convert("RGBA")
                image.thumbnail((24, 24))
        except (OSError, ValueError):
            continue
        axis.add_artist(AnnotationBbox(
            OffsetImage(np.asarray(image)),
            (0, position),
            xycoords=axis.get_yaxis_transform(),
            xybox=(-18, 0),
            boxcoords="offset points",
            frameon=False,
            annotation_clip=False,
        ))


def render_ranked_donut_chart(
    rows: Sequence[tuple[str, int]],
    *,
    other_count: int,
    title: str,
    context_label: str | None,
    center_unit: str,
    donut_title: str,
    filename: str,
    row_icons: Sequence[bytes | None] | None = None,
) -> discord.File:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = [_bounded_label(label) for label, _value in rows]
    values = [value for _label, value in rows]
    total_count = sum(values) + other_count
    if not values or total_count <= 0:
        raise ValueError("ranked donut chart requires positive data")
    if row_icons is not None and len(row_icons) != len(rows):
        raise ValueError("Each chart row must have one icon slot")

    bar_colors = list(SERIES_COLORS[: len(values)])
    figure_height = max(5.5, 1.5 + len(rows) * 0.5)
    figure = plt.figure(figsize=(13, figure_height))
    try:
        grid = figure.add_gridspec(1, 2, width_ratios=(3, 1.35), wspace=0.02)
        ranking_axis = figure.add_subplot(grid[0, 0])
        donut_axis = figure.add_subplot(grid[0, 1])

        _draw_ranking(ranking_axis, labels, values, bar_colors, total_count)
        if row_icons is not None and any(row_icons):
            _draw_row_icons(ranking_axis, row_icons)
        _draw_donut(
            donut_axis,
            values=values,
            colors=bar_colors,
            other_count=other_count,
            total_count=total_count,
            center_unit=center_unit,
            title=donut_title,
        )

        title_y = 0.97
        figure.suptitle(title, fontsize=16, y=title_y, va="center")
        if context_label is not None:
            figure.text(
                0.008,
                title_y,
                context_label,
                ha="left",
                va="center",
                fontsize=12,
                color="#52514e",
            )
        buffer = io.BytesIO()
        figure.savefig(buffer, format="png", bbox_inches="tight", dpi=160)
        buffer.seek(0)
        return discord.File(buffer, filename=filename)
    finally:
        plt.close(figure)
