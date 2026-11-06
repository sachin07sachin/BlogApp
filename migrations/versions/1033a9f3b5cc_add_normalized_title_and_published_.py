"""add normalized title and published title uniqueness

Revision ID: 1033a9f3b5cc
Revises: f2224ff0eff0
Create Date: 2026-11-05 18:14:45.261315

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1033a9f3b5cc'
down_revision = 'f2224ff0eff0'
branch_labels = None
depends_on = None


def normalize_title(title: str) -> str:
    """Normalize a title using the application's title policy."""
    if not title:
        return ""

    return " ".join(title.split()).casefold()


def upgrade():
    # 1. Add the new column as nullable initially.
    op.add_column(
        'blog_posts',
        sa.Column('normalized_title', sa.String(length=750), nullable=True)
    )

    # 2. Backfill existing posts using the same Python normalization
    # logic as the application.
    connection = op.get_bind()

    existing_posts = connection.execute(
        sa.text("SELECT id, title FROM blog_posts")
    ).mappings().all()

    updates = [
        {
            "post_id": post["id"],
            "normalized_title": normalize_title(post["title"])
        }
        for post in existing_posts
    ]

    if updates:
        connection.execute(
            sa.text("""
                UPDATE blog_posts
                SET normalized_title = :normalized_title
                WHERE id = :post_id
            """),
            updates
        )

    # 3. Ensure every existing post has a normalized title.
    op.alter_column(
        'blog_posts',
        'normalized_title',
        existing_type=sa.String(length=750),
        nullable=False
    )

    # 4. Remove the old global title uniqueness constraint.
    op.drop_constraint(
        'blog_posts_title_key',
        'blog_posts',
        type_='unique'
    )

    # 5. Enforce uniqueness only among published posts.
    op.create_index(
        'uq_blog_posts_normalized_title_published',
        'blog_posts',
        ['normalized_title'],
        unique=True,
        postgresql_where=sa.text('is_published = true')
    )


def downgrade():
    connection = op.get_bind()

    # Check whether the old global uniqueness rule can be restored.
    duplicate = connection.execute(
        sa.text("""
            SELECT title
            FROM blog_posts
            GROUP BY title
            HAVING COUNT(*) > 1
            LIMIT 1
        """)
    ).first()

    if duplicate:
        raise RuntimeError(
            "Cannot downgrade: duplicate original titles exist. "
            "Resolve duplicate titles before restoring the old "
            "global title uniqueness constraint."
        )

    # 1. Remove the partial unique index.
    op.drop_index(
        'uq_blog_posts_normalized_title_published',
        table_name='blog_posts'
    )

    # 2. Restore the original global uniqueness constraint.
    op.create_unique_constraint(
        'blog_posts_title_key',
        'blog_posts',
        ['title']
    )

    # 3. Remove the normalized title column.
    op.drop_column('blog_posts', 'normalized_title')

